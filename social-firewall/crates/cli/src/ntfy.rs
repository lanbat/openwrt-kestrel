//! Minimal plain-HTTP client for a self-hosted ntfy topic.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn push(topic_url: &str, message: &str) -> Result<()> {
    let url = topic_url
        .strip_prefix("http://")
        .context("ntfy topic URL must start with http:// (plain HTTP only)")?;
    let (host_port, path) = url
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((url, "/".to_string()));
    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .context("invalid port in ntfy topic URL")?,
        ),
        None => (host_port, 80),
    };
    let mut stream =
        TcpStream::connect((host, port)).with_context(|| format!("connecting to {host}:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let body = message.as_bytes();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let status_line = String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .context("could not parse ntfy HTTP status")?;
    if !(200..300).contains(&status) {
        bail!("ntfy push failed with HTTP status {status}: {status_line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;

    fn server(body: &'static str, status: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut received = vec![0; length];
            reader.read_exact(&mut received).unwrap();
            assert_eq!(received, body.as_bytes());
            write!(stream, "{status}\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        (format!("http://{addr}/social-firewall"), thread)
    }

    #[test]
    fn push_posts_raw_body() {
        let (url, thread) = server("hello", "HTTP/1.1 200 OK");
        push(&url, "hello").unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn push_rejects_non_2xx() {
        let (url, thread) = server("hello", "HTTP/1.1 500 Internal Server Error");
        assert!(push(&url, "hello").unwrap_err().to_string().contains("500"));
        thread.join().unwrap();
    }

    #[test]
    fn push_rejects_https() {
        assert!(push("https://ntfy.sh/topic", "hello").is_err());
    }
}
