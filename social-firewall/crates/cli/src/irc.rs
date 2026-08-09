//! LAN-only IRCv3 compatibility gateway for the signed partyline.
//!
//! IRC identities are local sessions. They never replace social-firewall
//! identities and never become peer-transport identities. Messages are
//! published through the existing signed partyline path.

mod auth;
mod channels;
mod commands;
mod delivery;
mod protocol;
mod session;
mod social;

use crate::group;
use anyhow::{Context, Result};
use domain_types::{GroupId, UserId};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use state_store::StateStore;
use std::collections::HashSet;
use std::fs::read;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

const BASE_CAPS: &[&str] = &["message-tags", "server-time"];
pub(crate) const LOCAL_CHANNEL: &str = "#sf-local";
pub(crate) const LOCAL_HISTORY_MAX_AGE: i64 = 7 * 24 * 60 * 60;
pub(crate) const LOCAL_HISTORY_MAX_MESSAGES: i64 = 500;
pub(crate) const LOCAL_HISTORY_MAX_BYTES: i64 = 1024 * 1024;

pub use auth::OidcSettings;
use auth::{decode_oauthbearer, OidcAuthenticator};
use channels::{channel_alias, find_group, group_members, member_nicks, valid_nick};
use delivery::{party_line_time_tags, send_message};
use protocol::{parse_line, server_time, IrcLine, MAX_LINE_BYTES};
use session::SessionState;

#[derive(Clone)]
struct Config {
    db: PathBuf,
    out_dir: PathBuf,
    fingerprint_socket: PathBuf,
    server_name: String,
    tls: Option<Arc<ServerConfig>>,
    oidc: Option<Arc<OidcAuthenticator>>,
}

trait IrcIo: Read + Write + Send {}
impl<T: Read + Write + Send> IrcIo for T {}
type SharedIo = Arc<Mutex<Box<dyn IrcIo>>>;

struct Client {
    id: u64,
    tx: mpsc::Sender<String>,
    state: Arc<Mutex<SessionState>>,
}

struct Server {
    config: Config,
    clients: Arc<Mutex<Vec<Client>>>,
    seen_messages: Arc<Mutex<HashSet<(GroupId, UserId, u64)>>>,
    next_client_id: AtomicU64,
}

pub fn listen(
    db: &Path,
    listen_addr: SocketAddr,
    server_name: &str,
    out_dir: &Path,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    oidc: Option<OidcSettings>,
) -> Result<()> {
    if listen_addr.ip().is_unspecified() {
        anyhow::bail!("IRC listener requires a specific LAN address, not {listen_addr}");
    }
    let tls = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some(load_tls_config(cert, key)?),
        (None, None) => anyhow::bail!("IRC TLS certificate and private key are required"),
        _ => anyhow::bail!("IRC TLS requires both certificate and private-key paths"),
    };
    let listener = TcpListener::bind(listen_addr)
        .with_context(|| format!("binding LAN-only IRC listener at {listen_addr}"))?;
    let server = Arc::new(Server {
        config: Config {
            db: db.to_path_buf(),
            out_dir: out_dir.to_path_buf(),
            fingerprint_socket: std::env::var_os("KESTRELD_FINGERPRINT_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/run/kestreld/fingerprint.sock")),
            server_name: server_name.to_string(),
            tls,
            oidc: oidc.map(OidcAuthenticator::new).transpose()?.map(Arc::new),
        },
        clients: Arc::new(Mutex::new(Vec::new())),
        seen_messages: Arc::new(Mutex::new(HashSet::new())),
        next_client_id: AtomicU64::new(1),
    });
    start_message_poller(Arc::clone(&server));
    println!("IRCv3 listener bound to {listen_addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let remote_addr = stream.peer_addr().ok();
                let server = Arc::clone(&server);
                thread::spawn(move || {
                    let io: SharedIo = match &server.config.tls {
                        Some(config) => match ServerConnection::new(Arc::clone(config)) {
                            Ok(connection) => {
                                Arc::new(Mutex::new(Box::new(StreamOwned::new(connection, stream))))
                            }
                            Err(error) => {
                                eprintln!("IRC TLS setup failed: {error}");
                                return;
                            }
                        },
                        None => Arc::new(Mutex::new(Box::new(stream))),
                    };
                    if let Err(error) = handle_client(server, io, remote_addr) {
                        eprintln!("IRC client ended: {error}");
                    }
                });
            }
            Err(error) => eprintln!("IRC accept failed: {error}"),
        }
    }
    Ok(())
}

fn start_message_poller(server: Arc<Server>) {
    thread::spawn(move || {
        let store = match StateStore::open(&server.config.db) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("IRC message poller could not open state store: {error}");
                return;
            }
        };
        seed_seen_messages(&server, &store);
        loop {
            poll_messages(&server, &store);
            thread::sleep(std::time::Duration::from_millis(500));
        }
    });
}

fn seed_seen_messages(server: &Server, store: &StateStore) {
    let mut seen = server.seen_messages.lock().unwrap();
    for group in store.list_groups().unwrap_or_default() {
        for message in store
            .list_party_line_messages(group.group_id)
            .unwrap_or_default()
        {
            seen.insert((message.group_id, message.author, message.sequence));
        }
    }
}

fn poll_direct_messages(server: &Server, store: &StateStore, self_user: Option<UserId>) {
    let mut recipients = self_user.into_iter().collect::<Vec<_>>();
    for identity in store.list_local_irc_identities().unwrap_or_default() {
        if !recipients.contains(&identity.user) {
            recipients.push(identity.user);
        }
    }
    for recipient in recipients {
        for message in store
            .list_direct_messages_for(&recipient)
            .unwrap_or_default()
        {
            let key = format!(
                "{}/{}",
                crate::tunnel::user_id_str(&message.sender),
                message.sequence
            );
            if store
                .has_been_notified("irc_direct_message", &key)
                .unwrap_or(false)
            {
                continue;
            }
            let sender = crate::tunnel::user_id_str(&message.sender);
            let clients = server.clients.lock().unwrap();
            let mut delivered = false;
            for client in clients.iter() {
                let state = client.state.lock().unwrap();
                let bound_user = state
                    .local_irc_identity
                    .as_ref()
                    .map(|identity| identity.user)
                    .or_else(|| {
                        state
                            .authenticated
                            .as_ref()
                            .and_then(|identity| identity.social_identity)
                    });
                if bound_user != Some(message.recipient) {
                    continue;
                }
                let Some(nickname) = state.nick.as_deref() else {
                    continue;
                };
                send_line(
                    &client.tx,
                    &format!(":sf/{sender} PRIVMSG {nickname} :{}", message.body),
                );
                delivered = true;
            }
            drop(clients);
            if delivered {
                let _ = store.mark_notified("irc_direct_message", &key, crate::now_unix());
            }
        }
    }
}

fn poll_messages(server: &Server, store: &StateStore) {
    let self_user = store
        .get_self_identity()
        .ok()
        .flatten()
        .map(|(user, _)| user);
    for group in store.list_groups().unwrap_or_default() {
        for message in store
            .list_party_line_messages(group.group_id)
            .unwrap_or_default()
        {
            let key = (message.group_id, message.author, message.sequence);
            if self_user == Some(message.author)
                || !server.seen_messages.lock().unwrap().insert(key)
            {
                continue;
            }
            let channel = channel_alias(&group);
            let clients = server.clients.lock().unwrap();
            for client in clients.iter() {
                if client
                    .state
                    .lock()
                    .unwrap()
                    .channels
                    .contains_key(&group.group_id)
                {
                    send_message(
                        &client.tx,
                        &server.config.server_name,
                        &channel,
                        &message,
                        store,
                    );
                }
            }
        }
    }
    poll_direct_messages(server, store, self_user);
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert_bytes = read(cert_path)
        .with_context(|| format!("opening IRC TLS certificate {}", cert_path.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading IRC TLS certificate PEM")?;
    let certs = if certs.is_empty() {
        vec![CertificateDer::from(cert_bytes)]
    } else {
        certs
    };
    let key_bytes = read(key_path)
        .with_context(|| format!("opening IRC TLS private key {}", key_path.display()))?;
    let key = match rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .context("reading IRC TLS private key PEM")?
    {
        Some(key) => key,
        None => PrivateKeyDer::try_from(key_bytes).map_err(anyhow::Error::msg)?,
    };
    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building IRC TLS server configuration")?,
    ))
}

fn handle_client(server: Arc<Server>, io: SharedIo, remote_addr: Option<SocketAddr>) -> Result<()> {
    let id = server.next_client_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel::<String>();
    let state = Arc::new(Mutex::new(SessionState {
        remote_addr,
        ..SessionState::default()
    }));
    let writer_io = Arc::clone(&io);
    thread::spawn(move || {
        while let Ok(line) = rx.recv() {
            let mut writer = writer_io.lock().unwrap();
            if writer.write_all(format!("{line}\r\n").as_bytes()).is_err() {
                break;
            }
            if writer.flush().is_err() {
                break;
            }
        }
    });

    server.clients.lock().unwrap().push(Client {
        id,
        tx: tx.clone(),
        state: Arc::clone(&state),
    });
    let store = StateStore::open(&server.config.db).context("opening IRC state store")?;
    if let Some(remote_addr) = remote_addr {
        if let Ok(Some(fingerprint)) =
            crate::device_fingerprint::lookup(&server.config.fingerprint_socket, remote_addr.ip())
        {
            state.lock().unwrap().device_fingerprint = Some(fingerprint);
        }
    }

    while let Some(line) = read_line(&io)? {
        if line.is_empty() {
            continue;
        }
        let parsed = match parse_line(&line) {
            Ok(parsed) => parsed,
            Err(error) => {
                send_error(
                    &tx,
                    &server.config.server_name,
                    &state,
                    417,
                    &error.to_string(),
                );
                continue;
            }
        };
        if commands::handle_line(&server, id, &tx, &state, &store, parsed)? {
            break;
        }
    }

    let nick = state.lock().unwrap().nick.clone();
    if let Some(nick) = nick {
        broadcast_all(
            &server,
            None,
            &format!(
                ":{nick}!local@{} QUIT :connection closed",
                server.config.server_name
            ),
        );
    }
    server
        .clients
        .lock()
        .unwrap()
        .retain(|client| client.id != id);
    Ok(())
}

fn read_line(io: &SharedIo) -> Result<Option<String>> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if io.lock().unwrap().read(&mut byte)? == 0 {
            return if raw.is_empty() {
                Ok(None)
            } else {
                anyhow::bail!("IRC connection ended mid-line")
            };
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\n") {
            break;
        }
        if raw.len() > MAX_LINE_BYTES + 2 {
            anyhow::bail!("IRC line exceeds 512-byte limit");
        }
    }
    Ok(Some(
        String::from_utf8(raw)?
            .trim_end_matches(['\r', '\n'])
            .to_string(),
    ))
}

fn handle_cap(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    params: &[String],
) {
    let capabilities = advertised_caps(server);
    let subcommand = params.first().map(|value| value.to_ascii_uppercase());
    match subcommand.as_deref() {
        Some("LS") => send_line(
            tx,
            &format!(
                ":{} CAP * LS :{}",
                server.config.server_name,
                capabilities.join(" ")
            ),
        ),
        Some("REQ") => {
            let requested = params
                .get(1)
                .map(|value| value.trim_start_matches(':'))
                .unwrap_or_default();
            let names: Vec<&str> = requested.split_whitespace().collect();
            let accepted: Vec<&str> = names
                .iter()
                .copied()
                .filter(|name| cap_supported(&capabilities, name))
                .collect();
            let rejected: Vec<&str> = names
                .iter()
                .copied()
                .filter(|name| !cap_supported(&capabilities, name))
                .collect();
            if !rejected.is_empty() {
                send_line(
                    tx,
                    &format!(
                        ":{} CAP * NAK :{}",
                        server.config.server_name,
                        rejected.join(" ")
                    ),
                );
            }
            if !accepted.is_empty() {
                state
                    .lock()
                    .unwrap()
                    .capabilities
                    .extend(accepted.iter().map(|value| (*value).to_string()));
                send_line(
                    tx,
                    &format!(
                        ":{} CAP * ACK :{}",
                        server.config.server_name,
                        accepted.join(" ")
                    ),
                );
            }
        }
        Some("END") => {}
        _ => send_line(
            tx,
            &format!(
                ":{} CAP * NAK :invalid capability request",
                server.config.server_name
            ),
        ),
    }
}

fn advertised_caps(server: &Server) -> Vec<String> {
    let mut capabilities: Vec<String> = BASE_CAPS.iter().map(|cap| (*cap).to_string()).collect();
    if server.config.oidc.is_some() {
        capabilities.push("sasl=OAUTHBEARER".into());
    }
    capabilities
}

fn cap_supported(capabilities: &[String], requested: &str) -> bool {
    capabilities.iter().any(|cap| {
        cap == requested || (requested.eq_ignore_ascii_case("sasl") && cap.starts_with("sasl="))
    })
}

fn has_write_access(server: &Server, state: &Arc<Mutex<SessionState>>) -> bool {
    let Some(authenticator) = &server.config.oidc else {
        return true;
    };
    state
        .lock()
        .unwrap()
        .authenticated
        .as_ref()
        .map(|identity| authenticator.has_write_access(identity))
        .unwrap_or(false)
}

fn has_operator_access(server: &Server, state: &Arc<Mutex<SessionState>>) -> bool {
    let Some(authenticator) = &server.config.oidc else {
        return true;
    };
    state
        .lock()
        .unwrap()
        .authenticated
        .as_ref()
        .map(|identity| authenticator.has_operator_access(identity))
        .unwrap_or(false)
}

fn handle_authenticate(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(authenticator) = &server.config.oidc else {
        send_error(
            tx,
            &server.config.server_name,
            state,
            904,
            "AUTHENTICATE :SASL is not enabled",
        );
        return;
    };
    let pending = state.lock().unwrap().sasl_pending;
    if pending {
        let response = params.first().map(String::as_str).unwrap_or("+");
        if response == "*" {
            state.lock().unwrap().sasl_pending = false;
            send_line(
                tx,
                &format!(
                    ":{} 906 * :SASL authentication aborted",
                    server.config.server_name
                ),
            );
            return;
        }
        let token = match decode_oauthbearer(response) {
            Ok(token) => token,
            Err(error) => {
                state.lock().unwrap().sasl_pending = false;
                send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    904,
                    &format!("AUTHENTICATE :{error}"),
                );
                return;
            }
        };
        match authenticator.authenticate(&token) {
            Ok(identity) => {
                let username = identity.username.clone();
                let subject = identity.subject.clone();
                let local_irc_identity = store
                    .get_local_irc_identity_by_subject(&identity.subject)
                    .ok()
                    .flatten();
                let mut session = state.lock().unwrap();
                session.sasl_pending = false;
                session.auth_groups = identity.groups.clone();
                session.auth_entitlements = identity.entitlements.clone();
                session.local_irc_identity = local_irc_identity;
                session.authenticated = Some(identity);
                if session.username.is_none() {
                    session.username = Some(username);
                }
                drop(session);
                send_line(
                    tx,
                    &format!(
                        ":{} 903 * :SASL authentication successful ({subject})",
                        server.config.server_name
                    ),
                );
                maybe_register(server, tx, state, store);
            }
            Err(error) => {
                eprintln!("IRC OIDC authentication failed: {error:#}");
                state.lock().unwrap().sasl_pending = false;
                send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    904,
                    &format!("AUTHENTICATE :{error}"),
                );
            }
        }
        return;
    }
    match params
        .first()
        .map(|value| value.to_ascii_uppercase())
        .as_deref()
    {
        Some("OAUTHBEARER") => {
            state.lock().unwrap().sasl_pending = true;
            send_line(tx, "+");
            if let Some(initial) = params.get(1) {
                handle_authenticate(server, tx, state, store, std::slice::from_ref(initial));
            }
        }
        _ => send_error(
            tx,
            &server.config.server_name,
            state,
            904,
            "AUTHENTICATE :Unsupported SASL mechanism",
        ),
    }
}

fn handle_nick(
    server: &Server,
    client_id: u64,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(nick) = params.first().filter(|nick| valid_nick(nick)) else {
        send_error(
            tx,
            &server.config.server_name,
            state,
            432,
            "* :Erroneous nickname",
        );
        return;
    };
    let clients = server.clients.lock().unwrap();
    let duplicate = clients.iter().any(|client| {
        if client.id == client_id {
            return false;
        }
        let current = client.state.lock().unwrap().nick.clone();
        current
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case(nick))
            .unwrap_or(false)
    });
    if duplicate {
        send_error(
            tx,
            &server.config.server_name,
            state,
            433,
            &format!("* {nick} :Nickname is already in use"),
        );
        return;
    }
    let (old, registered, mut channels, local_channel) = {
        let mut session = state.lock().unwrap();
        let old = session.nick.replace(nick.clone());
        (
            old,
            session.registered,
            session.channels.values().cloned().collect::<Vec<_>>(),
            session.local_channel,
        )
    };
    if local_channel {
        channels.push(LOCAL_CHANNEL.into());
    }
    drop(clients);
    if let Some(old) = old {
        let line = format!(":{old}!local@{} NICK :{nick}", server.config.server_name);
        if registered {
            for channel in channels {
                broadcast_channel_except(server, &channel, client_id, &line);
            }
        }
        send_line(tx, &line);
    }
    maybe_register(server, tx, state, store);
}

fn handle_user(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    if params.len() < 4 {
        send_error(
            tx,
            &server.config.server_name,
            state,
            461,
            "USER :Not enough parameters",
        );
        return;
    }
    state.lock().unwrap().username = Some(params[0].clone());
    maybe_register(server, tx, state, store);
}

fn maybe_register(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) {
    let mut session = state.lock().unwrap();
    if session.registered
        || session.nick.is_none()
        || session.username.is_none()
        || (server.config.oidc.is_some() && session.authenticated.is_none())
    {
        return;
    }
    session.registered = true;
    let nick = session.nick.clone().unwrap();
    let name = server.config.server_name.as_str();
    drop(session);
    send_line(
        tx,
        &format!(":{name} 001 {nick} :Welcome to the Kestrel LAN IRC gateway"),
    );
    send_line(tx, &format!(":{name} 002 {nick} :Your host is {name}"));
    send_line(
        tx,
        &format!(":{name} 003 {nick} :This server provides signed social-firewall party lines"),
    );
    send_line(
        tx,
        &format!(":{name} 004 {nick} {name} kestrel irc-3.0 +nt +mto"),
    );
    send_line(tx, &format!(":{name} 005 {nick} CHANTYPES=# CASEMAPPING=ascii NETWORK=Kestrel SAFELIST :are supported by this server"));
    send_motd(server, tx, state);
    join_local_channel(server, tx, state, store);
}

fn join_local_channel(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) {
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    {
        let mut session = state.lock().unwrap();
        if session.local_channel {
            return;
        }
        session.local_channel = true;
    }
    broadcast_local_channel(
        server,
        &format!(
            ":{nick}!local@{} JOIN {LOCAL_CHANNEL}",
            server.config.server_name
        ),
    );
    let _ = store.prune_local_irc_history(
        crate::now_unix(),
        LOCAL_HISTORY_MAX_AGE,
        LOCAL_HISTORY_MAX_MESSAGES,
        LOCAL_HISTORY_MAX_BYTES,
    );
    for (history_nick, body, issued_at) in store
        .list_local_irc_messages(LOCAL_HISTORY_MAX_MESSAGES as usize)
        .unwrap_or_default()
    {
        let timestamp = protocol::format_time(issued_at);
        send_line(
            tx,
            &format!(
                "@time={timestamp};sf-local=1 :{history_nick}!local@{} PRIVMSG {LOCAL_CHANNEL} :{body}",
                server.config.server_name
            ),
        );
    }
}

fn send_motd(server: &Server, tx: &mpsc::Sender<String>, state: &Arc<Mutex<SessionState>>) {
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    send_line(
        tx,
        &format!(
            ":{} 375 {nick} :- {} Message of the day",
            server.config.server_name, server.config.server_name
        ),
    );
    send_line(
        tx,
        &format!(
            ":{} 372 {nick} :- LAN-only IRCv3 gateway for signed party lines",
            server.config.server_name
        ),
    );
    send_line(
        tx,
        &format!(
            ":{} 376 {nick} :End of /MOTD command",
            server.config.server_name
        ),
    );
}

fn send_error(
    tx: &mpsc::Sender<String>,
    server: &str,
    state: &Arc<Mutex<SessionState>>,
    code: u16,
    text: &str,
) {
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    send_line(tx, &format!(":{server} {code:03} {nick} {text}"));
}

fn send_line(tx: &mpsc::Sender<String>, line: &str) {
    let mut end = line.len().min(MAX_LINE_BYTES);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    let _ = tx.send(line[..end].to_string());
}

fn broadcast_channel(server: &Server, channel: &str, line: &str) {
    broadcast_channel_except(server, channel, 0, line);
}

fn broadcast_channel_except(server: &Server, channel: &str, except: u64, line: &str) {
    let clients = server.clients.lock().unwrap();
    for client in clients.iter() {
        if client.id == except {
            continue;
        }
        if client
            .state
            .lock()
            .unwrap()
            .channels
            .values()
            .any(|current| current.eq_ignore_ascii_case(channel))
        {
            send_line(&client.tx, line);
        }
    }
}

fn broadcast_local_channel(server: &Server, line: &str) {
    for client in server.clients.lock().unwrap().iter() {
        if client.state.lock().unwrap().local_channel {
            send_line(&client.tx, line);
        }
    }
}

fn broadcast_local_channel_except(server: &Server, except: u64, line: &str) {
    for client in server.clients.lock().unwrap().iter() {
        if client.id != except && client.state.lock().unwrap().local_channel {
            send_line(&client.tx, line);
        }
    }
}

fn local_member_nicks(server: &Server) -> Vec<String> {
    server
        .clients
        .lock()
        .unwrap()
        .iter()
        .filter_map(|client| {
            let session = client.state.lock().unwrap();
            session.local_channel.then(|| session.nick.clone())
        })
        .flatten()
        .collect()
}

fn broadcast_all(server: &Server, except: Option<u64>, line: &str) {
    for client in server.clients.lock().unwrap().iter() {
        if except != Some(client.id) {
            send_line(&client.tx, line);
        }
    }
}

fn session_channel(
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    requested: Option<&String>,
) -> Option<(GroupId, String)> {
    let channels = state.lock().unwrap().channels.clone();
    if let Some(requested) = requested {
        let group = find_group(store, requested)?;
        return channels
            .get(&group.group_id)
            .cloned()
            .map(|channel| (group.group_id, channel));
    }
    channels.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn parses_capability_request_and_trailing_parameter() {
        assert_eq!(
            parse_line("@label=one CAP REQ :message-tags server-time").unwrap(),
            IrcLine {
                tags: vec![("label".into(), Some("one".into()))],
                command: "CAP".into(),
                params: vec!["REQ".into(), "message-tags server-time".into()],
            }
        );
    }

    #[test]
    fn preserves_empty_trailing_message_parameters_for_validation() {
        assert_eq!(
            parse_line("PRIVMSG #channel :").unwrap().params,
            vec!["#channel", ""]
        );
        assert_eq!(
            parse_line("PRIVMSG #channel ::leading-colon")
                .unwrap()
                .params,
            vec!["#channel", ":leading-colon"]
        );
    }

    #[test]
    fn parses_comma_separated_message_targets() {
        assert_eq!(
            parse_line("NOTICE #one,#two :hello").unwrap().params,
            vec!["#one,#two", "hello"]
        );
        assert_eq!(
            parse_line("JOIN #one,#two").unwrap().params,
            vec!["#one,#two"]
        );
        assert_eq!(
            parse_line("INVITE fed/local #group").unwrap().params,
            vec!["fed/local", "#group"]
        );
    }

    #[test]
    fn rejects_overlong_nicks_and_accepts_irc_specials() {
        assert!(valid_nick("alice_2"));
        assert!(valid_nick("[alice]"));
        assert!(!valid_nick("a name"));
        assert!(!valid_nick(&"a".repeat(31)));
    }

    #[test]
    fn channel_aliases_are_stable_ascii_slugs_with_id_suffixes() {
        let group_id = GroupId(domain_types::Hash32([0xab; 32]));
        assert_eq!(
            channels::channel_alias_for("Neighborhood Watch!", group_id),
            "#sf-neighborhood-watch-abababababab"
        );
        assert_eq!(
            channels::channel_alias_for("!!!", group_id),
            "#sf-group-abababababab"
        );
    }

    #[test]
    fn formats_epoch_server_time() {
        assert_eq!(protocol::format_time(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn decodes_oauthbearer_payload_without_accepting_plaintext_tokens() {
        let payload = "n,a=user,\u{1}auth=Bearer access-token\u{1}\u{1}";
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        assert_eq!(decode_oauthbearer(&encoded).unwrap(), "access-token");
        assert!(decode_oauthbearer("access-token").is_err());
    }

    #[test]
    fn authentik_group_and_entitlement_gates_fail_closed() {
        let identity = auth::AuthenticatedIdentity {
            subject: "sub-1".into(),
            username: "alice".into(),
            groups: vec!["router-users".into()],
            entitlements: vec!["router:write".into()],
            social_identity: None,
        };
        let client = reqwest::blocking::Client::new();
        let auth = OidcAuthenticator {
            client,
            introspection_url: "https://auth.example/introspect".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            issuer: None,
            audience: None,
            required_group: Some("router-users".into()),
            write_entitlement: Some("router:write".into()),
            operator_entitlement: Some("router:admin".into()),
            social_identity_claim: None,
        };
        assert!(auth::required_group_allowed(
            Some("router-users"),
            &identity.groups
        ));
        assert!(!auth::required_group_allowed(
            Some("router-admins"),
            &identity.groups
        ));
        assert!(auth.has_write_access(&identity));
        assert!(!auth.has_operator_access(&identity));
    }
}
