use super::{Server, SessionState};
use anyhow::{Context, Result};
use state_store::StateStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};

pub(crate) fn handle(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    body: &str,
) -> Result<()> {
    let words = crate::command_args::split(body.trim_start_matches("/sf").trim())?;
    let Some(command) = words.first().map(String::as_str) else {
        help(server, tx, state);
        return Ok(());
    };
    let options = parse_options(&words[1..])?;
    match command {
        "help" => help(server, tx, state),
        "groups" | "list-groups" => list_groups(server, tx, state, store)?,
        "follows" | "list-follows" => list_follows(server, tx, state, store)?,
        "history" | "list-party-line" => history(server, tx, state, store, &options)?,
        "create-group" => create_group(server, tx, state, store, &options)?,
        "invite" => invite(server, tx, state, store, &options)?,
        "topic" => announce_topic(server, tx, state, store, &options)?,
        "mode" => announce_mode(server, tx, state, store, &options)?,
        "voice" => announce_voice(server, tx, state, store, &options)?,
        "voting-right" => set_voting_right(server, tx, state, store, &options)?,
        "block" => block_user(server, tx, state, store, &options)?,
        "unblock" => unblock_user(server, tx, state, store, &options)?,
        "approve" => approve_join(server, tx, state, store, &options)?,
        "reject" => reject_join(server, tx, state, store, &options)?,
        "blocked" => list_blocked(server, tx, state, store, &options)?,
        "apply" => apply(server, tx, state, store, &options)?,
        "sync" => sync(server, tx, state, store, &options)?,
        "request-tunnel" => request_tunnel(server, tx, state, store, &options)?,
        "accept-tunnel" => accept_tunnel(server, tx, state, store, &options)?,
        "offer-tunnel" => offer_tunnel(server, tx, state, store, &options)?,
        "select-tunnel" => select_tunnel(server, tx, state, store, &options)?,
        "tunnel-trust" => tunnel_trust(server, tx, state, store, &options)?,
        "opinion" | "publish-opinion" => publish_opinion(server, tx, state, store, &options)?,
        "evaluate" | "evaluate-target" => evaluate_target(server, tx, state, store, &options)?,
        "vote" | "cast-group-vote" => cast_group_vote(server, tx, state, store, &options)?,
        "policy-vote" | "vote-policy-entry" => {
            vote_policy_entry(server, tx, state, store, &options)?
        }
        "policies" | "list-policies" => list_policies(server, tx, state, store)?,
        "policy-explain" | "explain-policy" => explain_policy(server, tx, state, store, &options)?,
        "tunnels" | "list-tunnels" => list_tunnels(server, tx, state, store)?,
        "pending-tunnels" => list_pending_tunnels(server, tx, state, store)?,
        "tunnel-balance" => list_tunnel_balances(server, tx, state, store)?,
        "lists" | "list-lists" => list_shared_lists(server, tx, state, store)?,
        "profiles" => list_profiles(server, tx, state, store)?,
        "routes" => list_routes(server, tx, state, store)?,
        "fingerprint" => list_fingerprint(server, tx, state, store, &options)?,
        _ => response(
            server,
            tx,
            state,
            &format!("unknown /sf command `{command}`; use /sf help"),
        ),
    }
    Ok(())
}

pub(crate) fn error(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    message: &str,
) {
    response(server, tx, state, &format!("error: {message}"));
}

pub(crate) fn handle_invite(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    params: &[String],
) -> Result<()> {
    if params.len() < 2 {
        super::send_error(
            tx,
            &server.config.server_name,
            state,
            461,
            "INVITE :Not enough parameters",
        );
        return Ok(());
    }
    require_write_access(server, tx, state)?;
    let target = crate::tunnel::user_id_str(&resolve_invite_target(store, &params[0])?);
    let channel = params[1].trim_start_matches(':');
    let group = crate::group::resolve_group_id(store, channel)?;
    crate::group::invite_group_member(
        store,
        &crate::group::group_id_str(group),
        &target,
        false,
        None,
    )?;
    let requester = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    super::send_line(
        tx,
        &format!(
            ":{} 341 {requester} {target} {channel}",
            server.config.server_name
        ),
    );
    response(
        server,
        tx,
        state,
        &format!(
            "invitation for {target} queued to {}",
            crate::group::group_id_str(group)
        ),
    );
    Ok(())
}

fn resolve_invite_target(store: &StateStore, target: &str) -> Result<domain_types::UserId> {
    if target.contains('/') {
        return crate::tunnel::parse_user_ref(target);
    }
    let matches = store
        .list_follows()?
        .into_iter()
        .filter(|follow| {
            follow
                .display_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(target))
        })
        .map(|follow| follow.user)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [user] => Ok(*user),
        [] => anyhow::bail!(
            "unknown IRC invite target `{target}`; use a follow label or FEDERATION_ID/LOCAL_ID"
        ),
        _ => anyhow::bail!("ambiguous IRC invite target `{target}`; use FEDERATION_ID/LOCAL_ID"),
    }
}

fn parse_options(words: &[String]) -> Result<HashMap<String, String>> {
    let mut options = HashMap::new();
    let mut index = 0;
    while index < words.len() {
        let key = words[index]
            .strip_prefix("--")
            .with_context(|| format!("expected an option, got `{}`", words[index]))?;
        let value = words
            .get(index + 1)
            .with_context(|| format!("missing value for `--{key}`"))?;
        options.insert(key.to_string(), value.clone());
        index += 2;
    }
    Ok(options)
}

fn help(server: &Server, tx: &mpsc::Sender<String>, state: &Arc<Mutex<SessionState>>) {
    for line in [
        "/sf groups | follows | history [--group GROUP]",
        "/sf opinion --target-kind KIND --target-value VALUE --stance STANCE --reason-code CODE [--note TEXT]",
        "/sf evaluate --target-kind KIND --target-value VALUE [--threshold NUMBER]",
        "/sf create-group --name NAME --description TEXT [--join-prompt TEXT]",
        "/sf invite --group GROUP --user FEDERATION/LOCAL [--voting true|false]",
        "/sf topic|mode|voice|voting-right|block|unblock ...",
        "/sf approve|reject|blocked ...",
        "/sf apply --dry-run true|false [--confirm true]",
        "/sf sync [--group GROUP]",
        "/sf request-tunnel --advertisement ADVERTISEMENT",
        "/sf accept-tunnel --requester USER --sequence NUMBER",
        "/sf offer-tunnel --description TEXT --target KIND:VALUE[,KIND:VALUE]",
        "/sf select-tunnel --advertisement REF --target KIND:VALUE[,KIND:VALUE]",
        "/sf tunnel-trust --user USER --auto-accept true|false",
        "/sf vote --group GROUP --target-kind KIND --target-value VALUE --stance STANCE --reason-code CODE [--note TEXT]",
        "/sf policy-vote --policy-id ID --entry-id ID --group GROUP --stance STANCE --reason-code CODE [--note TEXT]",
        "/sf policies | policy-explain --policy-id ID --entry-id ID --group GROUP",
        "/sf tunnels | pending-tunnels | tunnel-balance",
        "/sf lists | profiles | routes",
        "/sf fingerprint --group GROUP --fingerprint-id ID --revision NUMBER",
        "Mutating commands publish signed records; replication uses Iroh, Reticulum, or file fallback.",
    ] {
        response(server, tx, state, line);
    }
}

fn list_groups(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let groups = store.list_groups()?;
    if groups.is_empty() {
        response(server, tx, state, "no groups");
    }
    for group in groups {
        response(
            server,
            tx,
            state,
            &format!(
                "{} {} ({})",
                crate::group::group_id_str(group.group_id),
                group.name,
                group.description
            ),
        );
    }
    Ok(())
}

fn list_follows(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let follows = store.list_follows()?;
    if follows.is_empty() {
        response(server, tx, state, "no follows");
    }
    for follow in follows {
        response(
            server,
            tx,
            state,
            &format!(
                "follow {}/{} allow={} deny={}{}",
                follow.user.federation.0,
                follow.user.local_id,
                follow.allow_weight,
                follow.deny_weight,
                if follow.excluded { " excluded" } else { "" }
            ),
        );
    }
    Ok(())
}

fn history(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    let group = group_option(state, store, options)?;
    let messages = store.list_party_line_messages(group)?;
    if messages.is_empty() {
        response(server, tx, state, "no partyline history");
    }
    for message in messages.iter().rev().take(100).rev() {
        super::send_message(
            tx,
            &server.config.server_name,
            &crate::group::group_id_str(group),
            message,
            store,
        );
    }
    Ok(())
}

fn create_group(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    let group_id = crate::group::create_group_with_id(
        store,
        required(options, "name")?,
        required(options, "description")?,
        options.get("join-prompt").cloned(),
        None,
    )?;
    response(
        server,
        tx,
        state,
        &format!(
            "signed group created: {}",
            crate::group::group_id_str(group_id)
        ),
    );
    Ok(())
}

fn invite(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::invite_group_member(
        store,
        required(options, "group")?,
        required(options, "user")?,
        options
            .get("voting")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(false),
        None,
    )?;
    response(
        server,
        tx,
        state,
        "signed group invitation recorded and queued for delivery",
    );
    Ok(())
}

fn announce_topic(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::announce_topic(
        store,
        required(options, "group")?,
        required(options, "topic")?.to_string(),
    )?;
    response(server, tx, state, "signed group topic updated");
    Ok(())
}

fn announce_mode(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::announce_mode(
        store,
        required(options, "group")?,
        required(options, "moderated")?.parse()?,
    )?;
    response(server, tx, state, "signed group moderation state updated");
    Ok(())
}

fn announce_voice(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::announce_voice(
        store,
        required(options, "group")?,
        required(options, "user")?,
        required(options, "voiced")?.parse()?,
    )?;
    response(server, tx, state, "signed group voice state updated");
    Ok(())
}

fn set_voting_right(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::set_group_voting_right(
        store,
        required(options, "group")?,
        required(options, "user")?,
        required(options, "voting")?.parse()?,
        None,
    )?;
    response(server, tx, state, "signed group voting rights updated");
    Ok(())
}

fn block_user(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::block_group_user(
        store,
        required(options, "group")?,
        required(options, "user")?,
        required(options, "reason-code")?,
        options.get("note").cloned(),
        None,
    )?;
    response(server, tx, state, "signed group block report recorded");
    Ok(())
}

fn unblock_user(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::unblock_group_user(
        store,
        required(options, "group")?,
        required(options, "user")?,
    )?;
    response(server, tx, state, "group block removed locally");
    Ok(())
}

fn approve_join(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::approve_group_join(
        store,
        required(options, "group")?,
        required(options, "requester")?,
        required(options, "sequence")?.parse()?,
        options
            .get("voting")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(false),
        None,
    )?;
    response(server, tx, state, "signed group membership update recorded");
    Ok(())
}

fn reject_join(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::group::reject_group_join(
        store,
        required(options, "requester")?,
        required(options, "sequence")?.parse()?,
    )?;
    response(server, tx, state, "group join request rejected");
    Ok(())
}

fn list_blocked(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    let group = crate::group::resolve_group_id(store, required(options, "group")?)?;
    let blocked = store.list_blocked_group_users(group)?;
    if blocked.is_empty() {
        response(server, tx, state, "no blocked users");
    }
    for (user, reason) in blocked {
        response(
            server,
            tx,
            state,
            &format!(
                "blocked {}/{}: {:?}{}",
                user.federation.0,
                user.local_id,
                reason.code,
                reason
                    .note
                    .map(|note| format!(" — {note}"))
                    .unwrap_or_default()
            ),
        );
    }
    Ok(())
}

fn apply(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    if !super::has_operator_access(server, state) {
        response(server, tx, state, "IRC operator access is required");
        anyhow::bail!("IRC operator access denied")
    }
    let dry_run = options
        .get("dry-run")
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(true);
    if !dry_run && options.get("confirm").map(String::as_str) != Some("true") {
        anyhow::bail!("non-dry-run apply requires --confirm true")
    }
    let protected = crate::ProtectedDestinations::default().with_defaults();
    crate::apply_all(
        store,
        &crate::SystemCommandRunner,
        protected,
        PathBuf::from("/tmp/social-firewall-irc-apply"),
        1.0,
        dry_run,
        crate::now_unix(),
    )?;
    crate::profile::apply_dns(store, dry_run)?;
    response(
        server,
        tx,
        state,
        if dry_run {
            "policy apply dry-run completed"
        } else {
            "local firewall policy applied"
        },
    );
    Ok(())
}

fn sync(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    if let Some(group) = options.get("group") {
        crate::group::sync_group(store, group)?;
    } else {
        crate::group::sync_outbox(store)?;
    }
    response(server, tx, state, "synchronization completed");
    Ok(())
}

fn request_tunnel(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::tunnel::request_tunnel(store, required(options, "advertisement")?, None)?;
    response(server, tx, state, "signed tunnel request recorded");
    Ok(())
}

fn accept_tunnel(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::tunnel::accept_tunnel_request(
        store,
        required(options, "requester")?,
        required(options, "sequence")?.parse()?,
        None,
    )?;
    response(server, tx, state, "signed tunnel acceptance recorded");
    Ok(())
}

fn offer_tunnel(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    let targets = parse_targets(required(options, "target")?)?;
    let recipients = comma_values(options.get("recipient"));
    let tags = comma_values(options.get("tags"));
    crate::tunnel::offer_tunnel(
        store,
        required(options, "description")?,
        options.get("limitation").cloned(),
        &targets,
        tags,
        options
            .get("max-connections")
            .map(|value| value.parse())
            .transpose()?,
        options
            .get("max-bandwidth-kbps")
            .map(|value| value.parse())
            .transpose()?,
        options
            .get("visibility")
            .map(String::as_str)
            .unwrap_or("public"),
        &recipients,
        options.get("in-response-to").cloned(),
        None,
        None,
    )?;
    response(server, tx, state, "signed tunnel offer recorded");
    Ok(())
}

fn select_tunnel(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::tunnel::select_tunnel(
        store,
        required(options, "advertisement")?,
        &parse_targets(required(options, "target")?)?,
    )?;
    response(server, tx, state, "tunnel route targets selected");
    Ok(())
}

fn tunnel_trust(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    let user = crate::tunnel::parse_user_ref(required(options, "user")?)?;
    crate::tunnel::set_tunnel_trust(
        store,
        user,
        parse_bool(options, "auto-accept")?,
        parse_bool_or(options, "auto-consume", false)?,
        parse_bool_or(options, "auto-respond", false)?,
        parse_bool_or(options, "exclude", false)?,
        options.get("tag-filter").cloned(),
        options
            .get("min-reciprocity")
            .map(|value| value.parse())
            .transpose()?,
    )?;
    response(server, tx, state, "tunnel trust rule updated");
    Ok(())
}

fn parse_targets(value: &str) -> Result<Vec<(String, String)>> {
    value
        .split(',')
        .map(|target| {
            let (kind, value) = target
                .split_once(':')
                .with_context(|| format!("target `{target}` must use KIND:VALUE"))?;
            Ok((kind.to_string(), value.to_string()))
        })
        .collect()
}

fn comma_values(value: Option<&String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_bool(options: &HashMap<String, String>, key: &str) -> Result<bool> {
    options
        .get(key)
        .with_context(|| format!("missing --{key}"))?
        .parse()
        .with_context(|| format!("--{key} must be true or false"))
}

fn parse_bool_or(options: &HashMap<String, String>, key: &str, default: bool) -> Result<bool> {
    options
        .get(key)
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("--{key} must be true or false"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn cast_group_vote(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    let group = group_option(state, store, options)?;
    let self_user = store.get_self_identity()?.context("no router identity")?.0;
    let group_state = store.get_group(group)?.context("unknown group")?;
    if !group_state.voting_members.contains(&self_user) {
        anyhow::bail!("this identity is not a voting member of the group");
    }
    crate::group::cast_group_vote(
        store,
        &crate::group::group_id_str(group),
        required(options, "target-kind")?,
        required(options, "target-value")?,
        required(options, "stance")?,
        required(options, "reason-code")?,
        options.get("note").cloned(),
        options
            .get("ttl-seconds")
            .map(|value| value.parse())
            .transpose()?,
        None,
    )?;
    response(server, tx, state, "signed group vote recorded");
    Ok(())
}

fn publish_opinion(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::publish_opinion(
        store,
        required(options, "target-kind")?,
        required(options, "target-value")?,
        required(options, "stance")?,
        required(options, "reason-code")?,
        options.get("note").cloned(),
        options
            .get("ttl-seconds")
            .map(|value| value.parse())
            .transpose()?,
        None,
    )?;
    response(server, tx, state, "signed opinion recorded");
    Ok(())
}

fn evaluate_target(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    crate::evaluate_target(
        store,
        required(options, "target-kind")?,
        required(options, "target-value")?,
        options
            .get("threshold")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(1.0),
    )?;
    response(
        server,
        tx,
        state,
        "evaluation completed; inspect the router policy result",
    );
    Ok(())
}

fn vote_policy_entry(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    require_write_access(server, tx, state)?;
    crate::shared_policy::vote_policy_entry(
        store,
        required(options, "policy-id")?,
        required(options, "entry-id")?,
        required(options, "group")?,
        required(options, "stance")?,
        required(options, "reason-code")?,
        options.get("note").cloned(),
        None,
    )?;
    response(server, tx, state, "signed policy vote recorded");
    Ok(())
}

fn list_policies(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let policies = store.list_shared_policies()?;
    if policies.is_empty() {
        response(server, tx, state, "no shared policies");
    }
    for policy in policies {
        response(
            server,
            tx,
            state,
            &format!(
                "policy {} #{}: {} ({} entries)",
                policy.policy_id,
                policy.sequence,
                policy.name,
                policy.entries.len()
            ),
        );
    }
    Ok(())
}

fn explain_policy(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    let policy_id = crate::parse_hash32(required(options, "policy-id")?)?;
    let entry_id = crate::parse_hash32(required(options, "entry-id")?)?;
    let group = crate::group::resolve_group_id(store, required(options, "group")?)?;
    let policy = store
        .list_shared_policies()?
        .into_iter()
        .find(|policy| policy.policy_id == policy_id && policy.entry(&entry_id).is_some())
        .context("unknown policy or entry")?;
    match store.policy_stance_for(
        policy_id,
        entry_id,
        policy.sequence,
        group,
        crate::now_unix(),
    )? {
        Some((stance, allow, deny)) => response(
            server,
            tx,
            state,
            &format!(
                "policy result: {} (allow votes: {allow}, deny votes: {deny})",
                crate::stance_str(stance)
            ),
        ),
        None => response(server, tx, state, "policy result: no decision"),
    }
    Ok(())
}

fn list_tunnels(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let advertisements = store.list_tunnel_advertisements()?;
    if advertisements.is_empty() {
        response(server, tx, state, "no tunnel advertisements");
    }
    for advertisement in advertisements {
        response(
            server,
            tx,
            state,
            &format!(
                "tunnel {}/{} #{}: {} [{}]",
                advertisement.provider.federation.0,
                advertisement.provider.local_id,
                advertisement.sequence,
                advertisement.description,
                advertisement.endpoint_hint
            ),
        );
    }
    Ok(())
}

fn list_pending_tunnels(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let requests = store.list_pending_tunnel_connection_requests()?;
    if requests.is_empty() {
        response(server, tx, state, "no pending tunnel requests");
    }
    for request in requests {
        response(
            server,
            tx,
            state,
            &format!(
                "pending tunnel request from {}/{} #{}",
                request.requester.federation.0, request.requester.local_id, request.sequence
            ),
        );
    }
    Ok(())
}

fn list_tunnel_balances(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let balances = store.list_tunnel_balances()?;
    if balances.is_empty() {
        response(server, tx, state, "no tunnel balances");
    }
    for balance in balances {
        response(server, tx, state, &format!("tunnel balance: {balance:?}"));
    }
    Ok(())
}

fn list_shared_lists(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let lists = store.list_shared_rule_lists()?;
    if lists.is_empty() {
        response(server, tx, state, "no shared rule lists");
    }
    for list in lists {
        response(
            server,
            tx,
            state,
            &format!(
                "list {}/{} #{}: {} ({} entries)",
                list.author.federation.0,
                list.author.local_id,
                list.sequence,
                list.name,
                list.entries.len()
            ),
        );
    }
    Ok(())
}

fn list_profiles(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let profiles = store.list_local_profiles()?;
    if profiles.is_empty() {
        response(server, tx, state, "no local profiles");
    }
    for profile in profiles {
        response(
            server,
            tx,
            state,
            &format!(
                "profile {}: {} [{}]",
                profile.profile_id,
                profile.name,
                if profile.active { "active" } else { "inactive" }
            ),
        );
    }
    Ok(())
}

fn list_routes(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
) -> Result<()> {
    let routes = store.list_local_route_profiles()?;
    if routes.is_empty() {
        response(server, tx, state, "no local route profiles");
    }
    for route in routes {
        response(
            server,
            tx,
            state,
            &format!(
                "route {}: table={} interface={} [{}]",
                route.name,
                route.table,
                route.interface,
                if route.enabled { "enabled" } else { "disabled" }
            ),
        );
    }
    Ok(())
}

fn list_fingerprint(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<()> {
    let group = crate::group::resolve_group_id(store, required(options, "group")?)?;
    let fingerprint_id = domain_types::Hash32(crate::tunnel::bytes32(required(
        options,
        "fingerprint-id",
    )?)?);
    let revision: u64 = required(options, "revision")?.parse()?;
    let observations = store.list_fingerprint_observations(group, fingerprint_id, revision)?;
    let comments = store.list_fingerprint_comments(group, fingerprint_id, revision)?;
    if observations.is_empty() && comments.is_empty() {
        response(server, tx, state, "no fingerprint observations or comments");
    }
    for observation in observations {
        response(
            server,
            tx,
            state,
            &format!(
                "fingerprint observation {}/{}: {} confidence={} digest={}",
                observation.observer.federation.0,
                observation.observer.local_id,
                observation.signal_family,
                observation.confidence,
                observation.evidence_digest
            ),
        );
    }
    for comment in comments {
        response(
            server,
            tx,
            state,
            &format!(
                "fingerprint comment {}/{} #{}: {}",
                comment.author.federation.0,
                comment.author.local_id,
                comment.sequence,
                comment.body
            ),
        );
    }
    Ok(())
}

fn group_option(
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    options: &HashMap<String, String>,
) -> Result<domain_types::GroupId> {
    if let Some(group) = options.get("group") {
        return crate::group::resolve_group_id(store, group);
    }
    state
        .lock()
        .unwrap()
        .channels
        .keys()
        .next()
        .copied()
        .context("join a group or provide --group")
}

fn required<'a>(options: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("missing --{key}"))
}

fn require_write_access(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
) -> Result<()> {
    if super::has_write_access(server, state) {
        Ok(())
    } else {
        response(server, tx, state, "IRC write access is required");
        anyhow::bail!("IRC write access denied")
    }
}

fn response(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    message: &str,
) {
    let nick = state
        .lock()
        .unwrap()
        .nick
        .clone()
        .unwrap_or_else(|| "*".into());
    super::send_line(
        tx,
        &format!(
            ":{} NOTICE {nick} :[sf] {message}",
            server.config.server_name
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn parses_quoted_social_command_options() {
        let words = crate::command_args::split(
            "--group neighborhood --target-kind domain --target-value ads.example --note \"known tracker\"",
        )
        .unwrap();
        let options = parse_options(&words).unwrap();
        assert_eq!(options.get("group").unwrap(), "neighborhood");
        assert_eq!(options.get("note").unwrap(), "known tracker");
    }

    #[test]
    fn rejects_positional_social_command_arguments() {
        let words = vec!["group".into()];
        assert!(parse_options(&words).is_err());
    }
}
