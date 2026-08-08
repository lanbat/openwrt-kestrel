//! Unix-socket adapter for an external Reticulum bridge.
//!
//! The Rust workspace deliberately does not embed the Python Reticulum
//! runtime. A small bridge process owns RNS identities and interfaces, while
//! this adapter preserves the same `PeerTransport` envelope and dispatch
//! contract used by Iroh.

use crate::envelope::Envelope;
use crate::transport::{Dispatch, PeerTransport, TransportError};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"KRT1";
const OP_SEND: u8 = 1;
const OP_REQUEST: u8 = 2;
const OP_LISTEN: u8 = 3;
const STATUS_ACCEPTED: u8 = 0;
const STATUS_REJECTED: u8 = 1;
const STATUS_ERROR: u8 = 2;
const STATUS_RESPONSE: u8 = 3;
const MAX_ADDRESS_BYTES: usize = 1024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// A Reticulum destination is intentionally opaque to the application. The
/// external bridge maps this value to an RNS destination and returns the
/// authenticated source identity on receive.
pub struct ReticulumTransport {
    socket_path: PathBuf,
}

impl ReticulumTransport {
    pub fn new(socket_path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let socket_path = socket_path.as_ref().to_path_buf();
        if socket_path.as_os_str().is_empty() {
            return Err(TransportError::Other(
                "Reticulum socket path is empty".into(),
            ));
        }
        Ok(Self { socket_path })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn connect(&self) -> Result<UnixStream, TransportError> {
        UnixStream::connect(&self.socket_path).map_err(|error| {
            TransportError::Unreachable(format!("{}: {error}", self.socket_path.display()))
        })
    }

    fn transact(
        &self,
        opcode: u8,
        to: &str,
        envelope: &Envelope,
    ) -> Result<Response, TransportError> {
        validate_command(to, &envelope.encode())?;
        let mut stream = self.connect()?;
        write_command(&mut stream, opcode, to, &envelope.encode())?;
        read_response(&mut stream)
    }
}

enum Response {
    Accepted,
    Rejected(String),
    Error(String),
    Envelope(Envelope),
}

impl PeerTransport for ReticulumTransport {
    fn send(&self, to: &str, envelope: &Envelope) -> Result<(), TransportError> {
        match self.transact(OP_SEND, to, envelope)? {
            Response::Accepted => Ok(()),
            Response::Rejected(reason) => Err(TransportError::ApplicationRejected(reason)),
            Response::Error(error) => Err(TransportError::Other(error)),
            Response::Envelope(_) => Err(TransportError::Other(
                "Reticulum bridge returned a response to send".into(),
            )),
        }
    }

    fn request(&self, to: &str, envelope: &Envelope) -> Result<Envelope, TransportError> {
        match self.transact(OP_REQUEST, to, envelope)? {
            Response::Envelope(response) => Ok(response),
            Response::Rejected(reason) => Err(TransportError::ApplicationRejected(reason)),
            Response::Error(error) => Err(TransportError::Other(error)),
            Response::Accepted => Err(TransportError::Other(
                "Reticulum bridge accepted request without a response".into(),
            )),
        }
    }

    fn recv_and_dispatch(&self, dispatch: &Dispatch<'_>) -> Result<(), TransportError> {
        let mut stream = self.connect()?;
        write_command(&mut stream, OP_LISTEN, "", &[])?;
        loop {
            let (from, envelope) = read_inbound(&mut stream)?;
            match dispatch(&from, &envelope) {
                Ok(Some(response)) => {
                    write_bridge_response(&mut stream, STATUS_RESPONSE, &response.encode())?
                }
                Ok(None) => write_bridge_response(&mut stream, STATUS_ACCEPTED, &[])?,
                Err(error) => {
                    write_bridge_response(&mut stream, STATUS_REJECTED, error.as_bytes())?
                }
            }
        }
    }
}

fn write_command(
    stream: &mut UnixStream,
    opcode: u8,
    address: &str,
    envelope: &[u8],
) -> Result<(), TransportError> {
    let address = address.as_bytes();
    validate_command_bytes(address, envelope)?;
    stream.write_all(MAGIC).map_err(io_error)?;
    stream.write_all(&[opcode]).map_err(io_error)?;
    stream
        .write_all(&(address.len() as u16).to_be_bytes())
        .map_err(io_error)?;
    stream
        .write_all(&(envelope.len() as u32).to_be_bytes())
        .map_err(io_error)?;
    stream.write_all(address).map_err(io_error)?;
    stream.write_all(envelope).map_err(io_error)
}

fn validate_command(address: &str, envelope: &[u8]) -> Result<(), TransportError> {
    validate_command_bytes(address.as_bytes(), envelope)
}

fn validate_command_bytes(address: &[u8], envelope: &[u8]) -> Result<(), TransportError> {
    if address.len() > MAX_ADDRESS_BYTES || address.len() > u16::MAX as usize {
        return Err(TransportError::Other(
            "Reticulum address is too long".into(),
        ));
    }
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(TransportError::Other(
            "Reticulum envelope is too large".into(),
        ));
    }
    Ok(())
}

fn read_response(stream: &mut UnixStream) -> Result<Response, TransportError> {
    let status = read_u8(stream)?;
    let payload = read_blob(stream, MAX_ENVELOPE_BYTES)?;
    match status {
        STATUS_ACCEPTED => Ok(Response::Accepted),
        STATUS_REJECTED => Ok(Response::Rejected(text(payload)?)),
        STATUS_ERROR => Ok(Response::Error(text(payload)?)),
        STATUS_RESPONSE => Envelope::decode(&payload)
            .map(Response::Envelope)
            .map_err(|error| TransportError::Other(format!("invalid Reticulum response: {error}"))),
        other => Err(TransportError::Other(format!(
            "unknown Reticulum bridge response status {other}"
        ))),
    }
}

fn read_inbound(stream: &mut UnixStream) -> Result<(String, Envelope), TransportError> {
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).map_err(io_error)?;
    if &magic != MAGIC {
        return Err(TransportError::Other(
            "invalid Reticulum bridge frame".into(),
        ));
    }
    let address = read_blob(stream, MAX_ADDRESS_BYTES)?;
    let payload = read_blob(stream, MAX_ENVELOPE_BYTES)?;
    let from = String::from_utf8(address)
        .map_err(|_| TransportError::Other("Reticulum source address is not UTF-8".into()))?;
    let envelope = Envelope::decode(&payload)
        .map_err(|error| TransportError::Other(format!("invalid Reticulum envelope: {error}")))?;
    Ok((from, envelope))
}

fn write_bridge_response(
    stream: &mut UnixStream,
    status: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(TransportError::Other(
            "Reticulum response is too large".into(),
        ));
    }
    stream.write_all(&[status]).map_err(io_error)?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(io_error)?;
    stream.write_all(payload).map_err(io_error)
}

fn read_blob(stream: &mut UnixStream, max: usize) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(io_error)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(TransportError::Other("Reticulum frame is too large".into()));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).map_err(io_error)?;
    Ok(payload)
}

fn read_u8(stream: &mut UnixStream) -> Result<u8, TransportError> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).map_err(io_error)?;
    Ok(byte[0])
}

fn text(payload: Vec<u8>) -> Result<String, TransportError> {
    String::from_utf8(payload)
        .map_err(|_| TransportError::Other("Reticulum bridge error is not UTF-8".into()))
}

fn io_error(error: std::io::Error) -> TransportError {
    TransportError::Other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatementKind;

    #[test]
    fn rejects_oversized_addresses_and_envelopes_before_connecting() {
        let transport = ReticulumTransport::new("/tmp/missing-reticulum.sock").unwrap();
        let envelope = Envelope {
            kind: StatementKind::Group,
            payload: vec![0; MAX_ENVELOPE_BYTES + 1],
        };
        assert!(matches!(
            transport.send("destination", &envelope),
            Err(TransportError::Other(message)) if message.contains("too large")
        ));
        let envelope = Envelope {
            kind: StatementKind::Group,
            payload: vec![],
        };
        assert!(matches!(
            transport.send(&"x".repeat(MAX_ADDRESS_BYTES + 1), &envelope),
            Err(TransportError::Other(message)) if message.contains("too long")
        ));
    }

    #[test]
    fn socket_path_is_opaque_and_preserved() {
        let transport = ReticulumTransport::new("/run/kestrel/reticulum.sock").unwrap();
        assert_eq!(
            transport.socket_path(),
            Path::new("/run/kestrel/reticulum.sock")
        );
    }
}
