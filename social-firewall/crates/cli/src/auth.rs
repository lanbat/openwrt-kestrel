use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub uid: String,
    pub username: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    pub entitlements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    MissingIdentity,
    InvalidIdentity(&'static str),
    MissingEntitlement(String),
}

pub fn required() -> bool {
    matches!(
        std::env::var("AUTHENTIK_REQUIRED").as_deref(),
        Ok("1") | Ok("yes") | Ok("true")
    )
}

pub fn current() -> Result<Option<AuthenticatedUser>, &'static str> {
    let fields = std::env::vars().collect::<HashMap<_, _>>();
    parse_fields(|name| fields.get(name).map(String::as_str))
}

pub fn authorize_mutation() -> Result<(), AuthFailure> {
    let Some(user) = current().map_err(AuthFailure::InvalidIdentity)? else {
        if std::env::var_os("AUTHENTIK_WRITE_ENTITLEMENT").is_some() || required() {
            return Err(AuthFailure::MissingIdentity);
        }
        return Ok(());
    };
    let Some(entitlement) = std::env::var_os("AUTHENTIK_WRITE_ENTITLEMENT") else {
        return Ok(());
    };
    let entitlement = entitlement.to_string_lossy().into_owned();
    if user.entitlements.iter().any(|item| item == &entitlement) {
        Ok(())
    } else {
        Err(AuthFailure::MissingEntitlement(entitlement))
    }
}

fn parse_fields<'a>(
    get: impl Fn(&str) -> Option<&'a str>,
) -> Result<Option<AuthenticatedUser>, &'static str> {
    let uid = first_header(&get, "HTTP_X_AUTHENTICATED_UID", "HTTP_X_AUTHENTIK_UID");
    let username = first_header(
        &get,
        "HTTP_X_AUTHENTICATED_USER",
        "HTTP_X_AUTHENTIK_USERNAME",
    );
    if uid.is_none() && username.is_none() {
        return Ok(None);
    }
    let uid = uid.ok_or("missing X-authentik-uid")?;
    let username = username.ok_or("missing X-authentik-username")?;
    for value in [uid, username]
        .into_iter()
        .chain(first_header(
            &get,
            "HTTP_X_AUTHENTICATED_EMAIL",
            "HTTP_X_AUTHENTIK_EMAIL",
        ))
        .chain(first_header(
            &get,
            "HTTP_X_AUTHENTICATED_NAME",
            "HTTP_X_AUTHENTIK_NAME",
        ))
    {
        if value.is_empty() || value.len() > 512 || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err("invalid Authentik identity header");
        }
    }
    Ok(Some(AuthenticatedUser {
        uid: uid.into(),
        username: username.into(),
        email: first_header(&get, "HTTP_X_AUTHENTICATED_EMAIL", "HTTP_X_AUTHENTIK_EMAIL")
            .map(str::to_owned),
        name: first_header(&get, "HTTP_X_AUTHENTICATED_NAME", "HTTP_X_AUTHENTIK_NAME")
            .map(str::to_owned),
        groups: split_header(first_header(
            &get,
            "HTTP_X_AUTHENTICATED_GROUPS",
            "HTTP_X_AUTHENTIK_GROUPS",
        ))?,
        entitlements: split_header(first_header(
            &get,
            "HTTP_X_AUTHENTICATED_ENTITLEMENTS",
            "HTTP_X_AUTHENTIK_ENTITLEMENTS",
        ))?,
    }))
}

fn first_header<'a>(
    get: &impl Fn(&str) -> Option<&'a str>,
    generic: &str,
    authentik: &str,
) -> Option<&'a str> {
    get(generic).or_else(|| get(authentik))
}

fn split_header(value: Option<&str>) -> Result<Vec<String>, &'static str> {
    value
        .unwrap_or_default()
        .split('|')
        .filter(|item| !item.is_empty())
        .map(|item| {
            if item.len() > 256 || item.bytes().any(|b| b < 0x20 || b == 0x7f) {
                Err("invalid Authentik group header")
            } else {
                Ok(item.to_owned())
            }
        })
        .collect()
}

pub fn reject_response(reason: &str) -> String {
    format!(
        "Status: 401 Unauthorized\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\n\r\nAuthentik authentication required: {reason}"
    )
}

pub fn forbidden_response(reason: &str) -> String {
    format!(
        "Status: 403 Forbidden\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\n\r\nAuthentik authorization required: {reason}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields<'a>(values: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> + 'a {
        move |name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| *value)
        }
    }

    #[test]
    fn parses_identity_groups_and_entitlements() {
        let user = parse_fields(fields(&[
            ("HTTP_X_AUTHENTIK_UID", "uid-1"),
            ("HTTP_X_AUTHENTIK_USERNAME", "alice"),
            ("HTTP_X_AUTHENTIK_GROUPS", "admins|routers"),
            ("HTTP_X_AUTHENTIK_ENTITLEMENTS", "router:write"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.groups, ["admins", "routers"]);
        assert_eq!(user.entitlements, ["router:write"]);
    }

    #[test]
    fn prefers_provider_neutral_headers_over_authentik_headers() {
        let user = parse_fields(fields(&[
            ("HTTP_X_AUTHENTICATED_UID", "generic-uid"),
            ("HTTP_X_AUTHENTICATED_USER", "generic-user"),
            ("HTTP_X_AUTHENTIK_UID", "wrong-uid"),
            ("HTTP_X_AUTHENTIK_USERNAME", "wrong-user"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(user.uid, "generic-uid");
        assert_eq!(user.username, "generic-user");
    }

    #[test]
    fn partial_or_control_character_identity_is_rejected() {
        assert_eq!(
            parse_fields(fields(&[("HTTP_X_AUTHENTIK_UID", "uid-1")])),
            Err("missing X-authentik-username")
        );
        assert_eq!(
            parse_fields(fields(&[
                ("HTTP_X_AUTHENTIK_UID", "uid-1"),
                ("HTTP_X_AUTHENTIK_USERNAME", "alice\nadmin"),
            ])),
            Err("invalid Authentik identity header")
        );
    }

    #[test]
    fn entitlement_matching_is_exact() {
        let user = AuthenticatedUser {
            uid: "uid".into(),
            username: "alice".into(),
            email: None,
            name: None,
            groups: vec![],
            entitlements: vec!["router:write".into()],
        };
        assert!(user.entitlements.iter().any(|item| item == "router:write"));
        assert!(!user
            .entitlements
            .iter()
            .any(|item| item == "router:write-extra"));
    }
}
