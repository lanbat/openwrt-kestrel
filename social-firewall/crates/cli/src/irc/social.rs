use super::{Server, SessionState};
use anyhow::{Context, Result};
use state_store::StateStore;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};

pub(crate) fn handle(
    server: &Server,
    tx: &mpsc::Sender<String>,
    state: &Arc<Mutex<SessionState>>,
    store: &StateStore,
    body: &str,
) -> Result<()> {
    let words = shell_words::split(body.trim_start_matches("/sf").trim())?;
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
        "vote" | "cast-group-vote" => cast_group_vote(server, tx, state, store, &options)?,
        "policy-vote" | "vote-policy-entry" => {
            vote_policy_entry(server, tx, state, store, &options)?
        }
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
        "/sf vote --group GROUP --target-kind KIND --target-value VALUE --stance STANCE --reason-code CODE [--note TEXT]",
        "/sf policy-vote --policy-id ID --entry-id ID --group GROUP --stance STANCE --reason-code CODE [--note TEXT]",
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
        let words = shell_words::split(
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
