use super::{IrcLine, Server, SessionState};
use anyhow::Result;
use domain_types::GroupId;
use state_store::StateStore;
use std::sync::{mpsc, Arc, Mutex};

pub(crate) fn handle_line(
    server: &Server,
    client_id: u64,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    line: IrcLine,
) -> Result<bool> {
    let command = line.command.to_ascii_uppercase();
    if !matches!(
        command.as_str(),
        "CAP" | "PASS" | "AUTHENTICATE" | "NICK" | "USER" | "QUIT" | "PING" | "PONG"
    ) && !state.lock().unwrap().registered
    {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            451,
            &format!("{command} :You have not registered"),
        );
        return Ok(false);
    }
    match command.as_str() {
        "CAP" => super::handle_cap(server, tx, state, &line.params),
        "PING" => {
            if line.params.is_empty() {
                super::send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    409,
                    "* :No origin specified",
                );
            } else {
                super::send_line(
                    tx,
                    &format!(
                        ":{} PONG :{}",
                        server.config.server_name,
                        line.params.last().unwrap()
                    ),
                );
            }
        }
        "PONG" => {}
        "PASS" => {}
        "AUTHENTICATE" => super::handle_authenticate(server, tx, state, &line.params),
        "NICK" => super::handle_nick(server, client_id, tx, state, &line.params),
        "USER" => super::handle_user(server, tx, state, &line.params),
        "QUIT" => return Ok(true),
        "JOIN" => handle_join(server, tx, state, store, &line.params),
        "PART" => handle_part(server, tx, state, store, &line.params),
        "INVITE" => {
            if let Err(error) = super::social::handle_invite(server, tx, state, store, &line.params)
            {
                super::social::error(server, tx, state, &error.to_string());
            }
        }
        "PRIVMSG" | "NOTICE" => handle_message(
            server,
            client_id,
            tx,
            state,
            store,
            &line.params,
            command == "NOTICE",
        )?,
        "TOPIC" => handle_topic(server, tx, state, store, &line.params),
        "MODE" => handle_mode(server, tx, state, store, &line.params),
        "NAMES" => handle_names(server, tx, state, store, &line.params),
        "LIST" => handle_list(server, tx, store),
        "WHO" => handle_who(server, tx, state, store, &line.params),
        "WHOIS" => handle_whois(server, tx, store, &line.params),
        "MOTD" => super::send_motd(server, tx, state),
        "CAPAB" => {}
        _ => super::send_error(
            tx,
            &server.config.server_name,
            state,
            421,
            &format!("{command} :Unknown command"),
        ),
    }
    Ok(false)
}

fn handle_message(
    server: &Server,
    client_id: u64,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
    notice: bool,
) -> Result<()> {
    if params.len() < 2 {
        if !notice {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                461,
                "PRIVMSG :Not enough parameters",
            );
        }
        return Ok(());
    }
    let body = &params[1];
    if !notice && (body == "/sf" || body.starts_with("/sf ")) {
        if let Err(error) = super::social::handle(server, tx, state, store, body) {
            super::social::error(server, tx, state, &error.to_string());
        }
        return Ok(());
    }
    if body.is_empty() {
        if !notice {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                412,
                ":No text to send",
            );
        }
        return Ok(());
    }
    let mut target_groups = Vec::new();
    let joined = state.lock().unwrap().channels.clone();
    for target in params[0].split(',') {
        let Some(target_group) = super::find_group(store, target) else {
            if !notice {
                super::send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    403,
                    &format!("{target} :No such channel"),
                );
            }
            return Ok(());
        };
        let Some(channel) = joined.get(&target_group.group_id) else {
            if !notice {
                super::send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    404,
                    &format!("{target} :Cannot send to channel"),
                );
            }
            return Ok(());
        };
        if !target_groups
            .iter()
            .any(|(group_id, _): &(GroupId, String)| *group_id == target_group.group_id)
        {
            target_groups.push((target_group.group_id, channel.clone()));
        }
    }
    if target_groups.is_empty() {
        if !notice {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                411,
                "PRIVMSG :No recipient",
            );
        }
        return Ok(());
    }
    if !super::has_write_access(server, state) {
        if !notice {
            let channel = target_groups
                .first()
                .map(|(_, channel)| channel.as_str())
                .unwrap_or("*");
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                404,
                &format!("{channel} :You do not have IRC write access"),
            );
        }
        return Ok(());
    }
    let Some((self_user, _)) = store.get_self_identity().ok().flatten() else {
        return Ok(());
    };
    if body.len() > 4096 {
        if !notice {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                417,
                "* :Message length is invalid",
            );
        }
        return Ok(());
    }
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    let command = if notice { "NOTICE" } else { "PRIVMSG" };
    let now = super::server_time();
    for (group_id, channel) in target_groups {
        let Some(group) = store.get_group(group_id)? else {
            continue;
        };
        if !group.can_post_party_line(&self_user) {
            if !notice {
                super::send_error(
                    tx,
                    &server.config.server_name,
                    state,
                    404,
                    &format!("{channel} :Cannot send to channel"),
                );
            }
            continue;
        }
        super::group::publish_party_line(
            store,
            &super::group::group_id_str(group_id),
            body,
            None,
            &server.config.out_dir,
        )?;
        let line = format!(
            "@{} :{nick}!local@{} {command} {channel} :{body}",
            super::party_line_time_tags(now.clone(), now.clone()),
            server.config.server_name
        );
        super::broadcast_channel_except(server, &channel, client_id, &line);
        super::send_line(tx, &line);
    }
    Ok(())
}

fn handle_join(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(channels) = params.first() else {
        handle_join_one(server, tx, state, store, params);
        return;
    };
    for channel in channels.split(',') {
        let channel = channel.to_string();
        handle_join_one(server, tx, state, store, &[channel]);
    }
}

fn handle_join_one(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(channel) = params.first() else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            461,
            "JOIN :Not enough parameters",
        );
        return;
    };
    let Some(group) = super::find_group(store, channel) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            403,
            &format!("{channel} :No such channel"),
        );
        return;
    };
    let Some((self_user, _)) = store.get_self_identity().ok().flatten() else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            451,
            "JOIN :You have not registered a router identity",
        );
        return;
    };
    if !super::group_members(&group).contains(&self_user) {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            442,
            &format!("{channel} :You are not a member of this group"),
        );
        return;
    }
    let canonical = super::channel_alias(&group);
    if state.lock().unwrap().channels.contains_key(&group.group_id) {
        return;
    }
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    state
        .lock()
        .unwrap()
        .channels
        .insert(group.group_id, canonical.clone());
    super::broadcast_channel(
        server,
        &canonical,
        &format!(
            ":{nick}!local@{} JOIN {canonical}",
            server.config.server_name
        ),
    );
    super::send_line(
        tx,
        &format!(
            ":{} 332 {nick} {canonical} :{}",
            server.config.server_name, group.description
        ),
    );
    super::send_line(
        tx,
        &format!(
            ":{} 353 {nick} = {canonical} :{}",
            server.config.server_name,
            super::member_nicks(store, &group).join(" ")
        ),
    );
    super::send_line(
        tx,
        &format!(
            ":{} 366 {nick} {canonical} :End of /NAMES list",
            server.config.server_name
        ),
    );
    for message in store
        .list_party_line_messages(group.group_id)
        .unwrap_or_default()
        .iter()
        .rev()
        .take(100)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        super::send_message(tx, &server.config.server_name, &canonical, message, store);
    }
}

fn handle_part(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(channels) = params.first() else {
        handle_part_one(server, tx, state, store, params);
        return;
    };
    for channel in channels.split(',') {
        let channel = channel.to_string();
        handle_part_one(server, tx, state, store, &[channel]);
    }
}

fn handle_part_one(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(requested) = params.first() else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            442,
            "PART :You're not in a channel",
        );
        return;
    };
    let Some(group) = super::find_group(store, requested) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            403,
            &format!("{requested} :No such channel"),
        );
        return;
    };
    let Some(channel) = state.lock().unwrap().channels.get(&group.group_id).cloned() else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            442,
            "PART :You're not in that channel",
        );
        return;
    };
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    super::broadcast_channel(
        server,
        &channel,
        &format!(":{nick}!local@{} PART {channel}", server.config.server_name),
    );
    state.lock().unwrap().channels.remove(&group.group_id);
}

fn handle_topic(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some((group_id, channel)) = super::session_channel(state, store, params.first()) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            442,
            "TOPIC :You're not in a channel",
        );
        return;
    };
    let Some(group) = store.get_group(group_id).ok().flatten() else {
        return;
    };
    if params.get(1).is_some() && !super::has_operator_access(server, state) {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            482,
            &format!("{channel} :You do not have IRC operator access"),
        );
        return;
    }
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    match params.get(1) {
        None => super::send_line(
            tx,
            &format!(
                ":{} 332 {nick} {channel} :{}",
                server.config.server_name, group.description
            ),
        ),
        Some(topic) => {
            if let Some((self_user, _)) = store.get_self_identity().ok().flatten() {
                if !group.owners.contains(&self_user) && !group.admins.contains(&self_user) {
                    super::send_error(
                        tx,
                        &server.config.server_name,
                        state,
                        482,
                        &format!("{channel} :You're not a channel operator"),
                    );
                    return;
                }
                if let Err(error) = super::group::announce_topic(
                    store,
                    &super::group::group_id_str(group_id),
                    topic.trim_start_matches(':').to_string(),
                ) {
                    super::send_error(
                        tx,
                        &server.config.server_name,
                        state,
                        400,
                        &format!("TOPIC :{error}"),
                    );
                    return;
                }
                super::broadcast_channel(
                    server,
                    &channel,
                    &format!(
                        ":{nick}!local@{} TOPIC {channel} :{}",
                        server.config.server_name,
                        topic.trim_start_matches(':')
                    ),
                );
            }
        }
    }
}

fn handle_mode(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some((group_id, channel)) = super::session_channel(state, store, params.first()) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            442,
            "MODE :You're not in a channel",
        );
        return;
    };
    let Some(group) = store.get_group(group_id).ok().flatten() else {
        return;
    };
    if params.get(1).is_some() && !super::has_operator_access(server, state) {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            482,
            &format!("{channel} :You do not have IRC operator access"),
        );
        return;
    }
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    let Some(mode) = params.get(1) else {
        super::send_line(
            tx,
            &format!(
                ":{} 324 {nick} {channel} +{}",
                server.config.server_name,
                if group.party_line_moderated { "m" } else { "" }
            ),
        );
        return;
    };
    if mode != "+m" && mode != "-m" {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            472,
            &format!("{mode} :is unknown mode char to me"),
        );
        return;
    }
    if let Some((self_user, _)) = store.get_self_identity().ok().flatten() {
        if !group.owners.contains(&self_user) && !group.admins.contains(&self_user) {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                482,
                &format!("{channel} :You're not a channel operator"),
            );
            return;
        }
        let moderated = mode == "+m";
        if let Err(error) =
            super::group::announce_mode(store, &super::group::group_id_str(group_id), moderated)
        {
            super::send_error(
                tx,
                &server.config.server_name,
                state,
                400,
                &format!("MODE :{error}"),
            );
            return;
        }
        super::broadcast_channel(
            server,
            &channel,
            &format!(
                ":{nick}!local@{} MODE {channel} {mode}",
                server.config.server_name
            ),
        );
    }
}

fn handle_names(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let requested = params
        .first()
        .cloned()
        .or_else(|| state.lock().unwrap().channels.values().next().cloned());
    let Some(channel) = requested else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            461,
            "NAMES :Not enough parameters",
        );
        return;
    };
    let Some(group) = super::find_group(store, &channel) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            403,
            &format!("{channel} :No such channel"),
        );
        return;
    };
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    super::send_line(
        tx,
        &format!(
            ":{} 353 {nick} = {} :{}",
            server.config.server_name,
            super::channel_alias(&group),
            super::member_nicks(store, &group).join(" ")
        ),
    );
    super::send_line(
        tx,
        &format!(
            ":{} 366 {nick} {} :End of /NAMES list",
            server.config.server_name,
            super::channel_alias(&group)
        ),
    );
}

fn handle_list(server: &Server, tx: &mpsc::Sender<String>, store: &StateStore) {
    super::send_line(
        tx,
        &format!(":{} 321 * Channel :Users Name", server.config.server_name),
    );
    for group in store.list_groups().unwrap_or_default() {
        super::send_line(
            tx,
            &format!(
                ":{} 322 * {} {} :{}",
                server.config.server_name,
                super::channel_alias(&group),
                super::group_members(&group).len(),
                group.description
            ),
        );
    }
    super::send_line(
        tx,
        &format!(":{} 323 * :End of /LIST list", server.config.server_name),
    );
}

fn handle_who(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) {
    let Some(channel) = params.first() else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            461,
            "WHO :Not enough parameters",
        );
        return;
    };
    let Some(group) = super::find_group(store, channel) else {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            315,
            &format!("{channel} :End of /WHO list"),
        );
        return;
    };
    let requester = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    for member in super::member_nicks(store, &group) {
        super::send_line(
            tx,
            &format!(
                ":{} 352 {requester} {} local {} {} H :0 {}",
                server.config.server_name,
                super::channel_alias(&group),
                server.config.server_name,
                member,
                member
            ),
        );
    }
    super::send_line(
        tx,
        &format!(
            ":{} 315 {requester} {channel} :End of /WHO list",
            server.config.server_name
        ),
    );
}

fn handle_whois(server: &Server, tx: &mpsc::Sender<String>, store: &StateStore, params: &[String]) {
    let nick = params
        .get(1)
        .or_else(|| params.first())
        .cloned()
        .unwrap_or_default();
    let requester = "*";
    super::send_line(
        tx,
        &format!(
            ":{} 311 {requester} {nick} local {} * :LAN IRC session",
            server.config.server_name, nick
        ),
    );
    let groups = store
        .list_groups()
        .unwrap_or_default()
        .into_iter()
        .filter(|group| {
            super::member_nicks(store, group)
                .iter()
                .any(|value| value.eq_ignore_ascii_case(&nick))
        })
        .map(|group| super::channel_alias(&group))
        .collect::<Vec<_>>();
    super::send_line(
        tx,
        &format!(
            ":{} 319 {requester} {nick} :{}",
            server.config.server_name,
            groups.join(" ")
        ),
    );
    super::send_line(
        tx,
        &format!(
            ":{} 318 {requester} {nick} :End of /WHOIS list",
            server.config.server_name
        ),
    );
}
