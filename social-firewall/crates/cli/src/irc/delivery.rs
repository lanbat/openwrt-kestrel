use domain_types::PartyLineMessage;
use state_store::StateStore;
use std::sync::mpsc;

pub(crate) fn send_message(
    tx: &mpsc::Sender<String>,
    server: &str,
    channel: &str,
    message: &PartyLineMessage,
    store: &StateStore,
) {
    let nick = store
        .get_user_display_name(&message.author)
        .ok()
        .flatten()
        .unwrap_or_else(|| message.author.local_id.to_string()[..8].to_string());
    let received_at = store
        .party_line_message_received_at(message)
        .ok()
        .flatten()
        .unwrap_or(message.issued_at);
    let issued_at = crate::irc::protocol::format_time(message.issued_at);
    let received_at = crate::irc::protocol::format_time(received_at);
    super::send_line(
        tx,
        &format!(
            "@{} :{nick}!remote@{server} PRIVMSG {channel} :{}",
            party_line_time_tags(issued_at, received_at),
            message.body
        ),
    );
}

pub(crate) fn party_line_time_tags(issued_at: String, received_at: String) -> String {
    format!("time={issued_at};sf-issued-at={issued_at};sf-received-at={received_at}")
}
