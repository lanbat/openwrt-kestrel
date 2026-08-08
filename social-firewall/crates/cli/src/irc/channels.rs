use crate::group;
use domain_types::{Group, GroupId, UserId};
use state_store::StateStore;

pub(crate) fn find_group(store: &StateStore, channel: &str) -> Option<Group> {
    let value = channel.trim_start_matches('#');
    if let Some(id) = value.strip_prefix("sf-") {
        if let Ok(group_id) = group::parse_group_id(id) {
            return store.get_group(group_id).ok().flatten();
        }
    }
    let groups = store.list_groups().ok()?;
    if let Some(group) = groups
        .iter()
        .find(|group| group.name.eq_ignore_ascii_case(value))
    {
        return Some(group.clone());
    }
    if let Some(group) = groups.iter().find(|group| {
        channel_alias(group)
            .trim_start_matches('#')
            .eq_ignore_ascii_case(value)
    }) {
        return Some(group.clone());
    }
    let suffix = value.strip_prefix("sf-").unwrap_or(value);
    let matches = groups
        .iter()
        .filter(|group| group::group_id_str(group.group_id).starts_with(suffix))
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0].clone())
}

pub(crate) fn channel_name(group: &Group) -> String {
    format!("#sf-{}", group::group_id_str(group.group_id))
}

pub(crate) fn channel_alias(group: &Group) -> String {
    channel_alias_for(&group.name, group.group_id)
}

pub(crate) fn channel_alias_for(name: &str, group_id: GroupId) -> String {
    let slug = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "group" } else { &slug };
    format!("#{slug}-{}", &group::group_id_str(group_id)[..12])
}

pub(crate) fn member_nicks(store: &StateStore, group: &Group) -> Vec<String> {
    group_members(group)
        .iter()
        .map(|member| {
            let nick = store
                .get_user_display_name(member)
                .ok()
                .flatten()
                .unwrap_or_else(|| member.local_id.to_string()[..8].to_string());
            let prefix = if group.owners.contains(member) || group.admins.contains(member) {
                "@"
            } else if group.voiced_members.contains(member) {
                "+"
            } else {
                ""
            };
            format!("{prefix}{nick}")
        })
        .collect()
}

pub(crate) fn group_members(group: &Group) -> Vec<UserId> {
    group
        .owners
        .iter()
        .chain(&group.admins)
        .chain(&group.voting_members)
        .chain(&group.non_voting_members)
        .copied()
        .collect()
}

pub(crate) fn valid_nick(nick: &str) -> bool {
    !nick.is_empty()
        && nick.len() <= 30
        && nick
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "[]\\`_^{|}-".contains(c))
}
