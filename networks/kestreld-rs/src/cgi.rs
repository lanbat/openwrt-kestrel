use std::io::Read;
use std::path::PathBuf;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;

use crate::routes::{approve_access, approve_join, device, identity, network, plugin_info, qr, rotate_password};
use crate::state::AppState;

const BASE_DIR: &str = "/etc/kestrel/networks";
const SPLIT_ROUTING_DIR: &str = "/etc/kestrel/split-routing";
// Deliberately not "/tmp/kestreld/..." — that name collides with where
// test/qemu/deploy.sh (and any future deploy tooling) scp's the kestreld
// binary itself to /tmp/, which fails outright if this cache dir exists.
const CACHE_STATUS: &str = "/tmp/kestreld-cache/status.html";
const CACHE_TTL: u64 = 5;

pub fn is_cgi() -> bool {
    std::env::var("REQUEST_METHOD").is_ok()
}

pub async fn run() {
    let script = std::env::var("SCRIPT_NAME").unwrap_or_default();
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let query = std::env::var("QUERY_STRING").unwrap_or_default();
    let base_dir = PathBuf::from(BASE_DIR);
    let split_routing_dir = PathBuf::from(SPLIT_ROUTING_DIR);

    match (script.as_str(), method.as_str()) {
        ("/cgi-bin/status", "GET") => {
            respond_html(status_html(&base_dir, &split_routing_dir).await);
        }

        ("/cgi-bin/device", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let html = device::get(State(state), Query(q)).await;
            respond_html(html.0);
        }
        ("/cgi-bin/device", "POST") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let form = match parse_urlencoded(&read_body()) { Ok(f) => f, Err(e) => return respond_400(&format!("Invalid form: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let json = device::post(State(state), cgi_headers(), Query(q), Form(form)).await;
            respond_json(&json.0);
        }

        ("/cgi-bin/network", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let html = network::get(State(state), Query(q)).await;
            respond_html(html.0);
        }

        ("/cgi-bin/identity", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let html = identity::get(State(state), Query(q)).await;
            respond_html(html.0);
        }

        ("/cgi-bin/plugin_info", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let html = plugin_info::get(Query(q)).await;
            respond_html(html.0);
        }

        ("/cgi-bin/qr", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let resp = qr::get(State(state), Query(q)).await;
            respond_raw(resp);
        }

        ("/cgi-bin/approve-access", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let html = approve_access::get(State(state), Query(q)).await;
            respond_html(html.0);
        }
        ("/cgi-bin/approve-access", "POST") => {
            let form = match parse_urlencoded(&read_body()) { Ok(f) => f, Err(e) => return respond_400(&format!("Invalid form: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let json = approve_access::post(State(state), cgi_headers(), Form(form)).await;
            respond_json(&json.0);
        }

        ("/cgi-bin/approve-join", "GET") => {
            let q = match parse_urlencoded(&query) { Ok(q) => q, Err(e) => return respond_400(&format!("Invalid query: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let html = approve_join::get(State(state), Query(q)).await;
            respond_html(html.0);
        }
        ("/cgi-bin/approve-join", "POST") => {
            let form = match parse_urlencoded(&read_body()) { Ok(f) => f, Err(e) => return respond_400(&format!("Invalid form: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let json = approve_join::post(State(state), cgi_headers(), Form(form)).await;
            respond_json(&json.0);
        }

        ("/cgi-bin/rotate-password", "POST") => {
            let form = match parse_urlencoded(&read_body()) { Ok(f) => f, Err(e) => return respond_400(&format!("Invalid form: {e}")) };
            let state = AppState::new_once(base_dir, split_routing_dir).await;
            let json = rotate_password::post(State(state), Form(form)).await;
            respond_json(&json.0);
        }

        _ => respond_404(),
    }
}

async fn status_html(base_dir: &PathBuf, split_routing_dir: &PathBuf) -> String {
    if let Some(cached) = read_cache(CACHE_STATUS) {
        return cached;
    }
    let snap = crate::state::build_snapshot(base_dir, split_routing_dir).await;
    let html = crate::routes::status::render(&snap).await;
    write_cache(CACHE_STATUS, &html);
    html
}

fn read_cache(path: &str) -> Option<String> {
    let age = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    if age < CACHE_TTL { std::fs::read_to_string(path).ok() } else { None }
}

fn write_cache(path: &str, html: &str) {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, html);
}

/// Parse a `key=value&...` string (a raw QUERY_STRING or an
/// `application/x-www-form-urlencoded` POST body — same format either way)
/// into any of the route modules' Query/Form structs. Every field on those
/// structs is `Option<String>`, so a key missing entirely from the input
/// deserializes to `None` rather than failing.
fn parse_urlencoded<T: DeserializeOwned>(s: &str) -> Result<T, serde_urlencoded::de::Error> {
    serde_urlencoded::from_str(s)
}

/// Read the POST body from stdin, honoring CONTENT_LENGTH when present.
fn read_body() -> String {
    let len: usize = std::env::var("CONTENT_LENGTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut buf = Vec::new();
    if len > 0 {
        buf.resize(len, 0);
        if std::io::stdin().read_exact(&mut buf).is_err() {
            buf.clear();
        }
    } else {
        let _ = std::io::stdin().read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Build a HeaderMap from the CGI env vars the route handlers actually read
/// (Origin/Referer for the same-LAN check, X-Forwarded-For for audit logging).
fn cgi_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (env_name, header_name) in [
        ("HTTP_ORIGIN", "origin"),
        ("HTTP_REFERER", "referer"),
        ("HTTP_X_FORWARDED_FOR", "x-forwarded-for"),
    ] {
        if let Ok(val) = std::env::var(env_name) {
            if let Ok(value) = HeaderValue::from_str(&val) {
                headers.insert(HeaderName::from_static(header_name), value);
            }
        }
    }
    headers
}

fn respond_html(body: String) {
    print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}");
}

fn respond_json<T: serde::Serialize>(value: &T) {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    print!("Status: 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
}

/// Print a fully-formed axum response (used by /cgi-bin/qr, which sets its
/// own status code and headers for SVG/error bodies) as raw CGI output.
fn respond_raw(resp: axum::http::Response<String>) {
    let status = resp.status();
    let mut head = format!("Status: {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    print!("{head}{}", resp.body());
}

fn respond_400(msg: &str) {
    print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n{msg}");
}

fn respond_404() {
    print!("Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot found");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::device::DeviceQuery;

    #[test]
    fn parse_urlencoded_decodes_percent_and_missing_fields_as_none() {
        let q: DeviceQuery = parse_urlencoded("net=guest&mac=aa%3Abb%3Acc%3Add%3Aee%3Aff").unwrap();
        assert_eq!(q.net.as_deref(), Some("guest"));
        assert_eq!(q.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parse_urlencoded_empty_string_yields_all_none() {
        let q: DeviceQuery = parse_urlencoded("").unwrap();
        assert!(q.net.is_none());
        assert!(q.mac.is_none());
    }

    #[test]
    fn parse_urlencoded_passes_through_malformed_percent_encoding_lossily() {
        // Same underlying crate axum's Query/Form extractors use: invalid
        // %XX sequences are left as literal text rather than rejected.
        let q: DeviceQuery = parse_urlencoded("net=%zz").unwrap();
        assert_eq!(q.net.as_deref(), Some("%zz"));
    }

}
