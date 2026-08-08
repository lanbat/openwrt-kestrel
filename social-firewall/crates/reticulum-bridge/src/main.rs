use clap::Parser;
use rand_core::OsRng;
use reticulum::channel::{Channel, Message};
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex};

const MAGIC: &[u8; 4] = b"KRT1";
const OP_SEND: u8 = 1;
const OP_REQUEST: u8 = 2;
const OP_LISTEN: u8 = 3;
const STATUS_ACCEPTED: u8 = 0;
const STATUS_REJECTED: u8 = 1;
const STATUS_ERROR: u8 = 2;
const STATUS_RESPONSE: u8 = 3;
const MAX_ADDRESS_BYTES: usize = 1024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const FRAGMENT_HEADER: usize = 17;
// Reticulum-rs exposes a 2042-byte channel limit, but encrypted link packets
// also need room for the ephemeral key, IV, PKCS#7 padding, and HMAC. Stay
// below that implementation's effective plaintext limit to avoid its current
// buffer overflow panic when Fernet encryption is attempted.
const FRAGMENT_PAYLOAD: usize = 1800;
const APP_NAME: &str = "kestrel";
const APP_ASPECT: &str = "sync";
const REASSEMBLY_TTL: Duration = Duration::from_secs(120);

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "/run/kestrel/reticulum.sock")]
    socket: PathBuf,
    #[arg(
        long,
        default_value = "/etc/kestrel/social-firewall/reticulum.identity"
    )]
    identity: PathBuf,
    #[arg(long)]
    tcp_listen: Option<String>,
    #[arg(long)]
    tcp_connect: Option<String>,
    #[arg(long)]
    udp_bind: Option<String>,
    #[arg(long)]
    udp_forward: Option<String>,
}

#[derive(Clone, Debug)]
struct WireMessage {
    kind: u8,
    request_id: u64,
    total: u32,
    offset: u32,
    payload: Vec<u8>,
}

impl WireMessage {
    fn new(kind: u8, request_id: u64, total: usize, offset: usize, payload: &[u8]) -> Self {
        Self {
            kind,
            request_id,
            total: total as u32,
            offset: offset as u32,
            payload: payload.to_vec(),
        }
    }
}

impl Message for WireMessage {
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, reticulum::error::RnsError> {
        if message_type != 1 || packed.len() < FRAGMENT_HEADER {
            return Err(reticulum::error::RnsError::ChannelError);
        }
        let kind = packed[0];
        let request_id = u64::from_be_bytes(packed[1..9].try_into().unwrap());
        let total = u32::from_be_bytes(packed[9..13].try_into().unwrap());
        let offset = u32::from_be_bytes(packed[13..17].try_into().unwrap());
        let payload = packed[17..].to_vec();
        if total as usize > MAX_ENVELOPE_BYTES
            || offset as usize > total as usize
            || payload.len() > total as usize - offset as usize
        {
            return Err(reticulum::error::RnsError::ChannelError);
        }
        Ok(Self {
            kind,
            request_id,
            total,
            offset,
            payload,
        })
    }

    fn pack(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(FRAGMENT_HEADER + self.payload.len());
        result.push(self.kind);
        result.extend_from_slice(&self.request_id.to_be_bytes());
        result.extend_from_slice(&self.total.to_be_bytes());
        result.extend_from_slice(&self.offset.to_be_bytes());
        result.extend_from_slice(&self.payload);
        result
    }

    fn message_type(&self) -> u16 {
        1
    }
}

struct Reassembly {
    kind: u8,
    request_id: u64,
    bytes: Vec<u8>,
    received: Vec<bool>,
    updated_at: Instant,
}

impl Reassembly {
    fn add(&mut self, fragment: &WireMessage) -> Option<(u8, u64, Vec<u8>)> {
        if self.kind != fragment.kind
            || self.request_id != fragment.request_id
            || self.bytes.len() != fragment.total as usize
        {
            return None;
        }
        let start = fragment.offset as usize;
        let end = start + fragment.payload.len();
        if end > self.bytes.len() {
            return None;
        }
        for (index, byte) in fragment.payload.iter().enumerate() {
            if self.received[start + index] {
                return None;
            }
            self.bytes[start + index] = *byte;
            self.received[start + index] = true;
        }
        self.updated_at = Instant::now();
        if self.received.iter().all(|received| *received) {
            Some((self.kind, self.request_id, std::mem::take(&mut self.bytes)))
        } else {
            None
        }
    }
}

type SharedChannel = Arc<Channel<WireMessage>>;
type PendingResponse = oneshot::Sender<Result<Vec<u8>, String>>;

struct State {
    identity: PrivateIdentity,
    transport: Transport,
    destinations: HashMap<AddressHash, reticulum::destination::DestinationDesc>,
    channels: HashMap<AddressHash, SharedChannel>,
    pending: HashMap<u64, PendingResponse>,
    reassembly: HashMap<(reticulum::destination::link::LinkId, u64, u8), Reassembly>,
    remote_by_link: HashMap<reticulum::destination::link::LinkId, String>,
    listener: Option<Arc<Mutex<UnixStream>>>,
    next_request_id: u64,
}

impl State {
    async fn send_fragments(
        channel: &SharedChannel,
        kind: u8,
        request_id: u64,
        payload: &[u8],
    ) -> Result<(), String> {
        if payload.is_empty() || payload.len() > MAX_ENVELOPE_BYTES {
            return Err("Reticulum envelope size is outside configured limits".into());
        }
        for (offset, chunk) in payload.chunks(FRAGMENT_PAYLOAD).enumerate() {
            let offset = offset * FRAGMENT_PAYLOAD;
            let fragment = WireMessage::new(kind, request_id, payload.len(), offset, chunk);
            loop {
                if channel.is_ready().await {
                    channel
                        .send(&fragment)
                        .await
                        .map_err(|error| format!("Reticulum channel error: {error:?}"))?;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        Ok(())
    }
}

async fn channel_for(state: Arc<Mutex<State>>, address: &str) -> Result<SharedChannel, String> {
    let parsed = AddressHash::new_from_hex_string(address)
        .map_err(|error| format!("invalid Reticulum address: {error:?}"))?;
    let deadline = Instant::now() + Duration::from_secs(35);
    let destination = loop {
        let state = state.lock().await;
        if let Some(channel) = state.channels.get(&parsed).cloned() {
            return Ok(channel);
        }
        if let Some(destination) = state.destinations.get(&parsed).copied() {
            break destination;
        }
        drop(state);
        if Instant::now() >= deadline {
            return Err("Reticulum destination announcement timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let link = state.lock().await.transport.link(destination).await;
    loop {
        if link.lock().await.status() == reticulum::destination::link::LinkStatus::Active {
            let link_id = *link.lock().await.id();
            let identify_packet = {
                let state = state.lock().await;
                link.lock()
                    .await
                    .identify(&state.identity)
                    .map_err(|error| format!("Reticulum identity error: {error:?}"))?
            };
            state
                .lock()
                .await
                .transport
                .send_packet(identify_packet)
                .await;
            let (channel, incoming) = state
                .lock()
                .await
                .transport
                .mk_channel::<WireMessage>(link.clone())
                .await
                .map_err(|error| format!("Reticulum channel error: {error:?}"))?;
            let channel = Arc::new(channel);
            state.lock().await.channels.insert(parsed, channel.clone());
            spawn_channel_reader(state.clone(), link_id, channel.clone(), incoming);
            return Ok(channel);
        }
        if Instant::now() >= deadline {
            return Err("Reticulum link establishment timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn read_command(mut stream: UnixStream) -> Result<(u8, String, Vec<u8>, UnixStream), String> {
    let mut magic = [0u8; 4];
    stream
        .read_exact(&mut magic)
        .await
        .map_err(|error| error.to_string())?;
    if &magic != MAGIC {
        return Err("invalid bridge magic".into());
    }
    let opcode = stream.read_u8().await.map_err(|error| error.to_string())?;
    let address_len = stream.read_u16().await.map_err(|error| error.to_string())? as usize;
    let envelope_len = stream.read_u32().await.map_err(|error| error.to_string())? as usize;
    if address_len > MAX_ADDRESS_BYTES || envelope_len > MAX_ENVELOPE_BYTES {
        return Err("bridge frame exceeds configured limit".into());
    }
    let mut address = vec![0u8; address_len];
    let mut envelope = vec![0u8; envelope_len];
    stream
        .read_exact(&mut address)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .read_exact(&mut envelope)
        .await
        .map_err(|error| error.to_string())?;
    let address = String::from_utf8(address).map_err(|error| error.to_string())?;
    Ok((opcode, address, envelope, stream))
}

async fn write_response(stream: &mut UnixStream, status: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err("bridge response exceeds configured limit".into());
    }
    stream
        .write_u8(status)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_u32(payload.len() as u32)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| error.to_string())
}

async fn write_inbound(
    stream: &mut UnixStream,
    source: &str,
    envelope: &[u8],
) -> Result<(), String> {
    if source.len() > MAX_ADDRESS_BYTES || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err("bridge inbound frame exceeds configured limit".into());
    }
    stream
        .write_all(MAGIC)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_u32(source.len() as u32)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_u32(envelope.len() as u32)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(source.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(envelope)
        .await
        .map_err(|error| error.to_string())
}

async fn dispatch(
    state: Arc<Mutex<State>>,
    source: String,
    kind: u8,
    request_id: u64,
    payload: Vec<u8>,
    channel: SharedChannel,
) {
    log::debug!(
        "dispatching completed Kestrel message kind={} request_id={} from {}",
        kind,
        request_id,
        source
    );
    if matches!(kind, 3 | 4) {
        if let Some(sender) = state.lock().await.pending.remove(&request_id) {
            let _ = sender.send(if kind == 3 {
                Ok(payload)
            } else {
                Err(String::from_utf8_lossy(&payload).into())
            });
        }
        return;
    }
    let listener = { state.lock().await.listener.clone() };
    let Some(listener) = listener else {
        return;
    };
    let mut listener = listener.lock().await;
    if write_inbound(&mut listener, &source, &payload)
        .await
        .is_err()
    {
        return;
    }
    let status = match listener.read_u8().await {
        Ok(status) => status,
        Err(_) => return,
    };
    let length = match listener.read_u32().await {
        Ok(length) => length as usize,
        Err(_) => return,
    };
    if length > MAX_ENVELOPE_BYTES {
        return;
    }
    let mut response = vec![0u8; length];
    if listener.read_exact(&mut response).await.is_err() {
        return;
    }
    log::debug!(
        "received Kestrel dispatch status {} for request_id={}",
        status,
        request_id
    );
    match kind {
        1 => {}
        2 => {
            let response_kind = if status == STATUS_RESPONSE { 3 } else { 4 };
            let response_payload = response;
            let _ =
                State::send_fragments(&channel, response_kind, request_id, &response_payload).await;
        }
        _ => {}
    }
}

async fn handle_message(
    state: Arc<Mutex<State>>,
    link_id: reticulum::destination::link::LinkId,
    message: WireMessage,
    channel: SharedChannel,
) {
    let key = (link_id, message.request_id, message.kind);
    let complete = {
        let mut state = state.lock().await;
        state
            .reassembly
            .retain(|_, entry| entry.updated_at.elapsed() < REASSEMBLY_TTL);
        let entry = state.reassembly.entry(key).or_insert_with(|| Reassembly {
            kind: message.kind,
            request_id: message.request_id,
            bytes: vec![0; message.total as usize],
            received: vec![false; message.total as usize],
            updated_at: Instant::now(),
        });
        entry.add(&message)
    };
    if let Some((kind, request_id, payload)) = complete {
        if matches!(kind, 3 | 4) {
            dispatch(state, String::new(), kind, request_id, payload, channel).await;
            return;
        }
        let source = state.lock().await.remote_by_link.get(&link_id).cloned();
        if let Some(source) = source {
            dispatch(state, source, kind, request_id, payload, channel).await;
        }
    }
}

fn spawn_channel_reader(
    state: Arc<Mutex<State>>,
    link_id: reticulum::destination::link::LinkId,
    channel: SharedChannel,
    mut incoming: broadcast::Receiver<WireMessage>,
) {
    tokio::spawn(async move {
        while let Ok(message) = incoming.recv().await {
            log::debug!(
                "received Kestrel channel fragment on Reticulum link {}",
                link_id
            );
            handle_message(state.clone(), link_id, message, channel.clone()).await;
        }
        log::debug!(
            "Kestrel channel reader ended for Reticulum link {}",
            link_id
        );
    });
}

async fn accept_connections(listener: UnixListener, state: Arc<Mutex<State>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let result = read_command(stream).await;
            let Ok((opcode, address, envelope, mut stream)) = result else {
                return;
            };
            match opcode {
                OP_LISTEN => {
                    let mut state = state.lock().await;
                    if !address.is_empty() || !envelope.is_empty() {
                        let _ =
                            write_response(&mut stream, STATUS_ERROR, b"invalid listen command")
                                .await;
                        return;
                    }
                    // A crashed or restarted sf process cannot always be
                    // observed until the next inbound packet. Replacing the
                    // old listener makes receive-mode reconnectable.
                    state.listener = Some(Arc::new(Mutex::new(stream)));
                }
                OP_SEND | OP_REQUEST => {
                    let channel = match channel_for(state.clone(), &address).await {
                        Ok(channel) => channel,
                        Err(error) => {
                            let _ =
                                write_response(&mut stream, STATUS_ERROR, error.as_bytes()).await;
                            return;
                        }
                    };
                    let request_id = {
                        let mut state = state.lock().await;
                        let id = state.next_request_id;
                        state.next_request_id = state.next_request_id.wrapping_add(1);
                        id
                    };
                    if opcode == OP_SEND {
                        match State::send_fragments(&channel, 1, request_id, &envelope).await {
                            Ok(()) => {
                                let _ = write_response(&mut stream, STATUS_ACCEPTED, &[]).await;
                            }
                            Err(error) => {
                                let _ = write_response(&mut stream, STATUS_ERROR, error.as_bytes())
                                    .await;
                            }
                        }
                    } else {
                        let (response_tx, response_rx) = oneshot::channel();
                        state.lock().await.pending.insert(request_id, response_tx);
                        if let Err(error) =
                            State::send_fragments(&channel, 2, request_id, &envelope).await
                        {
                            state.lock().await.pending.remove(&request_id);
                            let _ =
                                write_response(&mut stream, STATUS_ERROR, error.as_bytes()).await;
                            return;
                        }
                        match tokio::time::timeout(Duration::from_secs(120), response_rx).await {
                            Ok(Ok(Ok(response))) => {
                                let _ =
                                    write_response(&mut stream, STATUS_RESPONSE, &response).await;
                            }
                            Ok(Ok(Err(error))) => {
                                let _ =
                                    write_response(&mut stream, STATUS_REJECTED, error.as_bytes())
                                        .await;
                            }
                            _ => {
                                let _ = write_response(
                                    &mut stream,
                                    STATUS_ERROR,
                                    b"Reticulum request timed out",
                                )
                                .await;
                            }
                        }
                    }
                }
                _ => {
                    let _ =
                        write_response(&mut stream, STATUS_ERROR, b"unknown bridge opcode").await;
                }
            }
        });
    }
}

async fn identity_at(path: &PathBuf) -> Result<PrivateIdentity, Box<dyn std::error::Error>> {
    if path.exists() {
        return PrivateIdentity::new_from_hex_string(tokio::fs::read_to_string(path).await?.trim())
            .map_err(|error| format!("invalid Reticulum identity: {error:?}").into());
    }
    let identity = PrivateIdentity::new_from_rand(OsRng);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, identity.to_hex_string()).await?;
    Ok(identity)
}

async fn configure_interfaces(transport: &Transport, args: &Args) {
    let manager = transport.iface_manager();
    if let Some(addr) = &args.tcp_listen {
        manager.lock().await.spawn(
            TcpServer::new(addr.clone(), manager.clone()),
            TcpServer::spawn,
        );
    }
    if let Some(addr) = &args.tcp_connect {
        manager
            .lock()
            .await
            .spawn(TcpClient::new(addr.clone()), TcpClient::spawn);
    }
    if let Some(bind) = &args.udp_bind {
        manager.lock().await.spawn(
            UdpInterface::new(bind.clone(), args.udp_forward.clone(), false),
            UdpInterface::spawn,
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let identity = identity_at(&args.identity).await?;
    let bridge_identity = identity.clone();
    let mut transport = TransportConfig::new("kestrel", &identity, true)
        .set_retransmit(true)
        .set_restart_outlinks(true)
        .build();
    configure_interfaces(&transport, &args).await;
    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, APP_ASPECT))
        .await;
    transport.send_announce(&destination, None).await;
    println!(
        "reticulum destination: {}",
        destination.lock().await.desc.address_hash.to_hex_string()
    );

    let parent = args
        .socket
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/run"));
    tokio::fs::create_dir_all(parent).await?;
    let _ = tokio::fs::remove_file(&args.socket).await;
    let listener = UnixListener::bind(&args.socket)?;
    let state = Arc::new(Mutex::new(State {
        identity: bridge_identity,
        transport,
        destinations: HashMap::new(),
        channels: HashMap::new(),
        pending: HashMap::new(),
        reassembly: HashMap::new(),
        remote_by_link: HashMap::new(),
        listener: None,
        next_request_id: 1,
    }));
    tokio::fs::set_permissions(
        &args.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .await?;
    tokio::spawn(accept_connections(listener, state.clone()));

    let mut announce_tick = tokio::time::interval(Duration::from_secs(10));
    let (mut announces, mut in_links) = {
        let state = state.lock().await;
        (
            state.transport.recv_announces().await,
            state.transport.in_link_events(),
        )
    };
    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                state.lock().await.transport.send_announce(&destination, None).await;
            }
            Ok(announce) = announces.recv() => {
                let destination = announce.destination.lock().await;
                log::debug!("learned Reticulum destination {}", destination.desc.address_hash);
                state.lock().await.destinations.insert(destination.desc.address_hash, destination.desc);
            }
            Ok(event) = in_links.recv() => {
                let event_kind = match &event.event {
                    LinkEvent::Activated => "activated",
                    LinkEvent::Closed => "closed",
                    LinkEvent::Data(_) => "data",
                    LinkEvent::Proof(_) => "proof",
                    LinkEvent::RemoteIdentified(_) => "identified",
                };
                log::debug!("received inbound Reticulum link event {}: {}", event.id, event_kind);
                match event.event {
                    LinkEvent::RemoteIdentified(identity) => {
                        state.lock().await.remote_by_link.insert(
                            event.id,
                            identity.address_hash.to_hex_string(),
                        );
                    }
                    LinkEvent::Activated => {
                        let link = { state.lock().await.transport.find_in_link(&event.id).await };
                        if let Some(link) = link {
                            if let Ok((channel, incoming)) = state.lock().await.transport.mk_channel::<WireMessage>(link).await {
                                let channel = Arc::new(channel);
                                log::debug!("bound Kestrel channel to inbound Reticulum link {}", event.id);
                                spawn_channel_reader(state.clone(), event.id, channel, incoming);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_round_trips() {
        let original = WireMessage::new(2, 17, 4, 2, b"cd");
        let decoded = WireMessage::unpack(&original.pack(), 1).unwrap();
        assert_eq!(decoded.kind, original.kind);
        assert_eq!(decoded.request_id, original.request_id);
        assert_eq!(decoded.total, original.total);
        assert_eq!(decoded.offset, original.offset);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn reassembly_accepts_out_of_order_fragments_once() {
        let mut reassembly = Reassembly {
            kind: 1,
            request_id: 9,
            bytes: vec![0; 4],
            received: vec![false; 4],
            updated_at: Instant::now(),
        };
        assert!(reassembly
            .add(&WireMessage::new(1, 9, 4, 2, b"cd"))
            .is_none());
        let complete = reassembly.add(&WireMessage::new(1, 9, 4, 0, b"ab"));
        assert_eq!(complete, Some((1, 9, b"abcd".to_vec())));
    }

    #[test]
    fn reassembly_rejects_duplicate_fragments() {
        let mut reassembly = Reassembly {
            kind: 1,
            request_id: 9,
            bytes: vec![0; 2],
            received: vec![false; 2],
            updated_at: Instant::now(),
        };
        let fragment = WireMessage::new(1, 9, 2, 0, b"ab");
        assert_eq!(reassembly.add(&fragment), Some((1, 9, b"ab".to_vec())));
        assert!(reassembly.add(&fragment).is_none());
    }
}
