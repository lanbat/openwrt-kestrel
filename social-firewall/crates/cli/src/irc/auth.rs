use anyhow::{Context, Result};
use base64::Engine;
use domain_types::UserId;
use std::fs::read;
use std::path::PathBuf;

#[derive(Clone)]
pub struct OidcSettings {
    pub introspection_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub ca_file: Option<PathBuf>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub required_group: Option<String>,
    pub write_entitlement: Option<String>,
    pub operator_entitlement: Option<String>,
    pub social_identity_claim: Option<String>,
}

pub(crate) struct OidcAuthenticator {
    pub(crate) client: reqwest::blocking::Client,
    pub(crate) introspection_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) issuer: Option<String>,
    pub(crate) audience: Option<String>,
    pub(crate) required_group: Option<String>,
    pub(crate) write_entitlement: Option<String>,
    pub(crate) operator_entitlement: Option<String>,
    pub(crate) social_identity_claim: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedIdentity {
    pub(crate) subject: String,
    pub(crate) username: String,
    pub(crate) groups: Vec<String>,
    pub(crate) entitlements: Vec<String>,
    pub(crate) social_identity: Option<UserId>,
}

impl OidcAuthenticator {
    pub(crate) fn new(settings: OidcSettings) -> Result<Self> {
        let mut client_builder = reqwest::blocking::Client::builder().https_only(true);
        if let Some(ca_file) = &settings.ca_file {
            let ca_bytes = read(ca_file)
                .with_context(|| format!("reading OIDC CA bundle {}", ca_file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&ca_bytes)
                .with_context(|| format!("parsing OIDC CA bundle {}", ca_file.display()))?;
            client_builder = client_builder.add_root_certificate(certificate);
        }
        Ok(Self {
            client: client_builder
                .build()
                .context("building Authentik OIDC client")?,
            introspection_url: settings.introspection_url,
            client_id: settings.client_id,
            client_secret: settings.client_secret,
            issuer: settings.issuer,
            audience: settings.audience,
            required_group: settings.required_group,
            write_entitlement: settings.write_entitlement,
            operator_entitlement: settings.operator_entitlement,
            social_identity_claim: settings.social_identity_claim,
        })
    }

    pub(crate) fn authenticate(&self, token: &str) -> Result<AuthenticatedIdentity> {
        let claims: serde_json::Value = self
            .client
            .post(&self.introspection_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .send()
            .context("requesting Authentik token introspection")?
            .error_for_status()
            .context("Authentik rejected token introspection")?
            .json()
            .context("decoding Authentik token introspection")?;
        if claims.get("active").and_then(|value| value.as_bool()) != Some(true) {
            anyhow::bail!("Authentik token is inactive");
        }
        if let Some(issuer) = &self.issuer {
            if claims.get("iss").and_then(|value| value.as_str()) != Some(issuer) {
                anyhow::bail!("Authentik token issuer mismatch");
            }
        }
        if let Some(audience) = &self.audience {
            let matches = claims
                .get("aud")
                .map(|value| {
                    value
                        .as_str()
                        .map(|item| item == audience)
                        .unwrap_or_else(|| {
                            value
                                .as_array()
                                .map(|items| {
                                    items.iter().any(|item| item.as_str() == Some(audience))
                                })
                                .unwrap_or(false)
                        })
                })
                .unwrap_or(false);
            if !matches {
                anyhow::bail!("Authentik token audience mismatch");
            }
        }
        let subject = claims
            .get("sub")
            .and_then(|value| value.as_str())
            .context("Authentik token has no subject")?;
        let username = claims
            .get("preferred_username")
            .or_else(|| claims.get("username"))
            .and_then(|value| value.as_str())
            .unwrap_or(subject);
        let identity = AuthenticatedIdentity {
            subject: subject.to_string(),
            username: username.to_string(),
            groups: string_claims(claims.get("groups")),
            entitlements: string_claims(claims.get("entitlements")),
            social_identity: parse_social_identity_claim(
                &claims,
                self.social_identity_claim.as_deref(),
            )?,
        };
        if !required_group_allowed(self.required_group.as_deref(), &identity.groups) {
            anyhow::bail!("Authentik group requirement not met");
        }
        Ok(identity)
    }

    pub(crate) fn has_write_access(&self, identity: &AuthenticatedIdentity) -> bool {
        self.write_entitlement
            .as_ref()
            .map(|required| identity.entitlements.iter().any(|item| item == required))
            .unwrap_or(true)
    }

    pub(crate) fn has_operator_access(&self, identity: &AuthenticatedIdentity) -> bool {
        self.operator_entitlement
            .as_ref()
            .map(|required| identity.entitlements.iter().any(|item| item == required))
            .unwrap_or(true)
    }
}

pub(crate) fn required_group_allowed(required: Option<&str>, groups: &[String]) -> bool {
    required
        .map(|required| groups.iter().any(|group| group == required))
        .unwrap_or(true)
}

fn string_claims(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_social_identity_claim(
    claims: &serde_json::Value,
    claim: Option<&str>,
) -> Result<Option<UserId>> {
    match claim {
        Some(claim) => claims
            .get(claim)
            .and_then(|value| value.as_str())
            .map(crate::tunnel::parse_user_ref)
            .transpose(),
        None => Ok(None),
    }
}

pub(crate) fn decode_oauthbearer(value: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("invalid OAUTHBEARER base64")?;
    let payload = String::from_utf8(bytes).context("invalid OAUTHBEARER payload")?;
    let token = payload
        .split('\u{1}')
        .find_map(|field| field.strip_prefix("auth=Bearer "))
        .or_else(|| payload.strip_prefix("Bearer "))
        .context("OAUTHBEARER payload has no bearer token")?;
    if token.is_empty() || token.len() > 16 * 1024 {
        anyhow::bail!("invalid OAUTHBEARER token length");
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_social_identity_claim;

    #[test]
    fn social_identity_claim_is_optional() {
        let claims = serde_json::json!({"social_user": "not-used"});
        assert!(parse_social_identity_claim(&claims, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn social_identity_claim_requires_a_valid_user_reference() {
        let claims = serde_json::json!({"social_user": "invalid"});
        assert!(parse_social_identity_claim(&claims, Some("social_user")).is_err());
    }

    #[test]
    fn missing_social_identity_claim_fails_closed_to_no_binding() {
        let claims = serde_json::json!({});
        assert!(parse_social_identity_claim(&claims, Some("social_user"))
            .unwrap()
            .is_none());
    }
}
