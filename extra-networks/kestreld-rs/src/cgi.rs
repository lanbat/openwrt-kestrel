use std::path::PathBuf;

const CACHE_STATUS: &str = "/tmp/kestreld/status.html";
const CACHE_TTL: u64 = 5;

pub fn is_cgi() -> bool {
    std::env::var("REQUEST_METHOD").is_ok()
}

pub async fn run() {
    let script = std::env::var("SCRIPT_NAME").unwrap_or_default();
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let query  = std::env::var("QUERY_STRING").unwrap_or_default();

    match (script.as_str(), method.as_str()) {
        ("/cgi-bin/status", _) => {
            let html = status_html().await;
            respond(&html);
        }
        ("/cgi-bin/device", "POST") => {
            let net = qs_get(&query, "net");
            let mac = qs_get(&query, "mac");
            print!("Status: 303 See Other\r\nLocation: /cgi-bin/device?net={net}&mac={mac}\r\n\r\n");
        }
        ("/cgi-bin/device", _) => {
            let net = qs_get(&query, "net");
            let mac = qs_get(&query, "mac");
            if !validate_net(&net) {
                respond("<h1>Invalid network</h1>");
                return;
            }
            if !validate_mac(&mac) {
                respond("<h1>Invalid MAC</h1>");
                return;
            }
            let html = crate::routes::device::render(&net, &mac);
            respond(&html);
        }
        _ => {
            print!("Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot found");
        }
    }
}

async fn status_html() -> String {
    if let Some(cached) = read_cache(CACHE_STATUS) {
        return cached;
    }
    let snap = crate::state::build_snapshot(&PathBuf::from("/etc/extra-networks")).await;
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
    let _ = std::fs::create_dir_all("/tmp/kestreld");
    let _ = std::fs::write(path, html);
}

fn respond(html: &str) {
    print!("Content-Type: text/html\r\n\r\n{html}");
}

fn qs_get(qs: &str, key: &str) -> String {
    qs.split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then(|| v.replace('+', " "))
        })
        .unwrap_or_default()
}

fn validate_net(net: &str) -> bool {
    !net.is_empty() && net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.chars().enumerate().all(|(i, c)| {
            if i % 3 == 2 { c == ':' } else { c.is_ascii_hexdigit() }
        })
}
