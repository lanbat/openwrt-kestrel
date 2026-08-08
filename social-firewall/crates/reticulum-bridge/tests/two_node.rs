#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

const MAGIC: &[u8; 4] = b"KRT1";
const OP_SEND: u8 = 1;
const OP_REQUEST: u8 = 2;
const OP_LISTEN: u8 = 3;
const STATUS_ACCEPTED: u8 = 0;
const STATUS_RESPONSE: u8 = 3;

struct Node {
    child: Child,
    stdout: BufReader<ChildStdout>,
    socket: PathBuf,
    identity: PathBuf,
}

impl Node {
    fn start(
        binary: &Path,
        root: &Path,
        name: &str,
        tcp_listen: &str,
        tcp_connect: Option<&str>,
    ) -> Self {
        let socket = root.join(format!("{name}.sock"));
        let identity = root.join(format!("{name}.identity"));
        let mut command = Command::new(binary);
        command
            .env("RUST_LOG", "warn")
            .arg("--socket")
            .arg(&socket)
            .arg("--identity")
            .arg(&identity)
            .arg("--tcp-listen")
            .arg(tcp_listen)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(tcp_connect) = tcp_connect {
            command.arg("--tcp-connect").arg(tcp_connect);
        }
        let mut child = command.spawn().expect("start Reticulum bridge node");
        let stdout = BufReader::new(child.stdout.take().expect("bridge stdout"));
        Self {
            child,
            stdout,
            socket,
            identity,
        }
    }

    fn destination(&mut self) -> String {
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .expect("read Reticulum destination");
        line.strip_prefix("reticulum destination: ")
            .expect("destination output")
            .trim()
            .to_string()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.identity);
    }
}

fn exact(stream: &mut UnixStream, length: usize) -> Vec<u8> {
    let mut buffer = vec![0; length];
    stream.read_exact(&mut buffer).expect("read bridge frame");
    buffer
}

fn connect_socket(path: &Path) -> UnixStream {
    for _ in 0..600 {
        match UnixStream::connect(path) {
            Ok(stream) => return stream,
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    panic!(
        "Reticulum bridge socket did not become ready: {}",
        path.display()
    );
}

fn command(stream: &mut UnixStream, opcode: u8, address: &[u8], payload: &[u8]) {
    stream.write_all(MAGIC).unwrap();
    stream.write_all(&[opcode]).unwrap();
    stream
        .write_all(&(address.len() as u16).to_be_bytes())
        .unwrap();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(address).unwrap();
    stream.write_all(payload).unwrap();
}

fn response(stream: &mut UnixStream) -> (u8, Vec<u8>) {
    let status = exact(stream, 1)[0];
    let length = u32::from_be_bytes(exact(stream, 4).try_into().unwrap()) as usize;
    (status, exact(stream, length))
}

fn inbound(stream: &mut UnixStream) -> (String, Vec<u8>) {
    assert_eq!(exact(stream, 4), MAGIC);
    let source_length = u32::from_be_bytes(exact(stream, 4).try_into().unwrap()) as usize;
    let payload_length = u32::from_be_bytes(exact(stream, 4).try_into().unwrap()) as usize;
    let source = String::from_utf8(exact(stream, source_length)).unwrap();
    (source, exact(stream, payload_length))
}

#[test]
fn two_nodes_exchange_authenticated_fragmented_messages() {
    let root = std::env::temp_dir().join(format!("kestrel-reticulum-test-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_kestrel-reticulum-bridge"));
    let mut node_a = Node::start(&binary, &root, "a", "127.0.0.1:45771", None);
    let mut node_b = Node::start(
        &binary,
        &root,
        "b",
        "127.0.0.1:45772",
        Some("127.0.0.1:45771"),
    );
    let _destination_a = node_a.destination();
    let destination_b = node_b.destination();
    let address = destination_b.as_bytes();
    let mut listener = connect_socket(&node_b.socket);
    listener
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    command(&mut listener, OP_LISTEN, &[], &[]);

    let payload = [vec![4], vec![b'x'; 4_999]].concat();
    let mut sender = connect_socket(&node_a.socket);
    sender
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    command(&mut sender, OP_SEND, address, &payload);
    let (source, received) = inbound(&mut listener);
    assert_eq!(source.len(), 32);
    assert_eq!(received, payload);
    listener.write_all(&[STATUS_ACCEPTED, 0, 0, 0, 0]).unwrap();
    assert_eq!(response(&mut sender), (STATUS_ACCEPTED, vec![]));

    let request_payload = vec![4, b'r', b'e', b'q'];
    let mut requester = connect_socket(&node_a.socket);
    requester
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    command(&mut requester, OP_REQUEST, address, &request_payload);
    let (_, received_request) = inbound(&mut listener);
    assert_eq!(received_request, request_payload);
    let response_payload = vec![11, b'o', b'k'];
    listener.write_all(&[STATUS_RESPONSE]).unwrap();
    listener
        .write_all(&(response_payload.len() as u32).to_be_bytes())
        .unwrap();
    listener.write_all(&response_payload).unwrap();
    assert_eq!(
        response(&mut requester),
        (STATUS_RESPONSE, response_payload)
    );
}
