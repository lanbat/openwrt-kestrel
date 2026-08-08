# Reticulum Bridge Protocol

`p2p-transport` uses a separate native Rust Reticulum process through a Unix
domain socket. The social-firewall process owns application envelopes and
dispatch decisions; the bridge owns the Reticulum identity, interfaces, path
discovery, links, and delivery.

The socket must be protected with filesystem permissions appropriate for the
router. It must not be exposed on a network listener.

## Client Commands

Every client command starts with:

```text
magic       4 bytes: ASCII KRT1
opcode      1 byte
address    2 bytes: big-endian UTF-8 byte length
envelope   4 bytes: big-endian byte length
address    UTF-8 opaque Reticulum destination
envelope   encoded p2p-transport Envelope bytes
```

Opcodes:

| Opcode | Meaning |
|---:|---|
| 1 | Send an envelope and wait for delivery status |
| 2 | Send an envelope and wait for a response envelope |
| 3 | Enter receive mode; address and envelope are empty |

The address is opaque to the Rust application. The bridge maps it to a
Reticulum destination and supplies an authenticated source address for inbound
frames.

## Responses

Send and request commands receive:

```text
status      1 byte
payload     4 bytes: big-endian byte length
payload     status-dependent bytes
```

Status values:

| Status | Meaning | Payload |
|---:|---|---|
| 0 | Accepted | Empty |
| 1 | Application rejected | UTF-8 reason |
| 2 | Bridge or transport error | UTF-8 reason |
| 3 | Response envelope | Encoded Envelope bytes |

## Receive Mode

After a listen command, the bridge sends repeated inbound frames:

```text
magic       4 bytes: ASCII KRT1
source      4 bytes: big-endian UTF-8 byte length
envelope    4 bytes: big-endian byte length
source      authenticated opaque Reticulum source address
envelope    encoded p2p-transport Envelope bytes
```

The Rust process dispatches the envelope through the same signature, replay,
follow, and ingest checks used by every other transport. It replies with the
response status format above: status 0 for accepted, status 1 for application
rejection, or status 3 with an optional response envelope.

## Limits

- Addresses are limited to 1024 bytes.
- Envelopes and response payloads are limited to 64 KiB.
- The bridge fragments larger application envelopes into reliable Reticulum
  channel messages without changing the application envelope.
- Reticulum authentication never replaces signed application statements or
  local follow authorization.
