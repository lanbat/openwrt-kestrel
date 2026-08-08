# Fingerprints, Keys, And UI Integration

This document defines how `kestreld` device fingerprints and
`social-firewall` group observations fit together. The two programs remain
separate packages and workspaces.

## Technical Decision Record

### Keep local and shared identity separate

**Approach:** `kestreld` owns private device identity and matching; social-
firewall owns signed, group-scoped evidence. A shared fingerprint is evidence
for review, not a replacement for a local identity.

**Reason:** local observations contain router-specific context and may be
ambiguous. A remote router must not be able to rename a local device or change
local enforcement merely by publishing a matching claim.

**Evidence:** `kestreld`'s matcher is explicitly scored and human-confirmed in
`networks/kestreld-rs/src/data/fingerprint.rs`; social observations are signed
and scoped by group in `crates/domain-types/src/fingerprint.rs`. This is a
verified implementation fact, not only a design preference.

### Use versioned, length-delimited canonical material

**Approach:** serialize a fixed signal-field order with a version byte and a
32-bit length before every value.

**Reason:** field order must remain stable across two independently deployed
routers, and delimiters prevent concatenation ambiguity. A version permits a
future incompatible signal format without silently changing the meaning of an
old ID.

**Evidence:** the collision-boundary test in
`crates/crypto/src/shared_fingerprint.rs` distinguishes `ab + c` from `a +
bc`; the kestreld material test verifies that local and sensitive fields are
excluded. Cross-version interoperability has not yet been tested between
compiled kestreld and `sf` binaries.

### Use a group-keyed BLAKE3 derivation

**Approach:** derive `BLAKE3 keyed_hash(group_key, canonical_material)` with a
32-byte key per group.

**Reason:** the existing `crypto` crate already uses BLAKE3 for content hashes,
and keyed derivation gives unrelated groups different namespaces without
publishing raw evidence. A public group ID alone would provide namespace
separation but would not provide a secret correlation boundary.

**Evidence:** the existing `crypto::hash` implementation and dependency are
already BLAKE3-based. Tests verify same-key stability and different-key
separation. Key agreement, rotation, compromise recovery, and entropy quality
of operator-supplied keys are not yet validated by the system.

### Share normalized evidence, never raw traffic

**Approach:** include only bounded normalized signal families in the shared
material; exclude MACs, IPs, cookies, raw headers, labels, and timestamps.

**Reason:** raw traffic and router-local identifiers create unnecessary privacy
risk and make cross-router comparison depend on network location. Normalized
signals still permit review while limiting disclosure.

**Evidence:** `FingerprintRecord` separates normalized fields from local MAC,
label, timestamp, cookie, and header fields; the kestreld privacy test checks
that excluded values do not enter canonical material. This reduces but does
not eliminate re-identification risk: uncommon signal combinations can still
be identifying.

### Keep materialization explicit and previewable

**Approach:** route effects render in `sf preview-routes` and
`sf apply --dry-run`; actual route/VPN mutation is not enabled until a backend
and QEMU tests exist. DNS output is managed and dnsmasq reload is OpenWrt-gated.

**Reason:** a signed remote statement describes intent, not permission to run
arbitrary local commands. Preview and capability checks let the operator see
what the local router can actually enforce.

**Evidence:** current code contains no route command execution in the preview
path; route-profile tests cover local profile validation and target capability
selection. The host dnsmasq reload guard was added after the documented Debian
PolicyKit prompt hazard was observed in `CONTRIBUTING.md`.

### Integrate the UIs with same-origin links, not shared code

**Approach:** retain separate CGI binaries and workspaces, but use stable
same-origin links and shared operator context between `/cgi-bin/*` and
`/cgi-bin/sf-*`.

**Reason:** this preserves independent packaging and failure boundaries while
using uhttpd's existing authentication. Iframes and compile-time coupling
would add deployment and session complexity without improving the trust model.

**Evidence:** `kestreld` is invoked as a CGI process per request and
`social-firewall` installs its own CGI symlinks. Same-origin integration is
therefore technically compatible; the dashboard cards and cross-links remain
planned UI work rather than verified behavior.

## Evidence Confidence And Limits

The following claims have different epistemic status:

| Claim | Status | Evidence or limitation |
|---|---|---|
| Local kestreld IDs are opaque and local | Verified | `FingerprintRecord` uses generated IDs and per-network storage. |
| Shared observations are signed and group-scoped | Verified | Domain types, crypto contexts, migrations, and ingest tests. |
| Same group key/material derives the same ID | Verified | Shared-fingerprint unit tests. |
| Different group keys separate IDs | Verified | Key-separation unit test. |
| Canonical material excludes sensitive local fields | Verified | kestreld material unit test and field selection code. |
| The derived ID identifies a physical device | Not established | Similar devices can have similar normalized signals; human review remains required. |
| Two real routers interoperate byte-for-byte | Partially established | Both implementations use the documented format, but no cross-binary fixture or two-router test exists yet. |
| Group keys are securely distributed | Not implemented | Keys are manually provisioned; no group key agreement exists. |
| Shared observations are automatically exported from kestreld | Not implemented | The material builder exists, but UI export and publication handoff are still absent. |
| Route preview is safe from route mutation | Verified locally | Preview tests and code path do not invoke `ip`, nftables, VPN, or UCI commands. |
| DNS tests cannot prompt for host privileges | Verified by guard | Reload requires OpenWrt markers; explicit overrides are opt-in. |

When changing the derivation format, key handling, or identity association,
update this evidence table and add a regression test before changing the
implementation.

## Two Identity Layers

### Local kestreld identity

`kestreld` keeps a private, router-local `FingerprintRecord` per network. Its
opaque generated ID, label, MAC history, timestamps, and local evidence are not
global identifiers. The matcher uses scored evidence to suggest that a new
privacy-MAC device may be an existing device; it never silently merges or
reapplies a label.

Local evidence may include normalized:

- DHCP options and vendor information.
- WiFi capabilities.
- mDNS name and model.
- Bounded TLS ClientHello and QUIC initial fingerprints when collection is
  explicitly enabled.

Raw packets, raw HTTP headers, cookies, browsing history, IP addresses, and MAC
addresses must not leave the router. Packet capture remains opt-in through
`FINGERPRINT_PACKET_CAPTURE=yes`.

### Shared social fingerprint

`social-firewall` stores a group-scoped `FingerprintObservation`. It is signed
by the observing router and contains only:

- Group ID.
- Shared fingerprint ID and revision.
- Signal family.
- Evidence digest.
- Observer confidence from `0` to `100`, timestamps, expiry, and signature.

Confidence is an observer-reported quality score, not a calibrated probability
that the fingerprint belongs to a particular identity. `0` means the observer
does not consider the observation useful; `100` is the observer's strongest
confidence. Ingest rejects values outside this range, and the score is covered
by the observation signature.

It does not contain raw evidence or the group fingerprint key. Comments and
future votes refer to `(group_id, fingerprint_id, fingerprint_revision)` so
later observations cannot rewrite the context of earlier discussion.

Neither shared ID means "proven physical device identity." It means that the
normalized evidence was sufficiently similar under one group's derivation
key. Local association still requires explicit human confirmation.

## Shared ID Derivation

The canonical material format is versioned and length-delimited:

```text
version = 1
length + dhcp_options
length + dhcp_vendor
length + wifi_capabilities
length + mdns_name
length + mdns_model
length + tls_clienthello
length + quic_initial
```

The material intentionally excludes local IDs, labels, MACs, IPs, cookies,
raw HTTP headers, TCP connection details, and timestamps. Length delimiters
prevent ambiguous concatenations such as `ab + c` versus `a + bc`.

The shared ID is:

```text
id = BLAKE3 keyed hash(group_fingerprint_key, canonical_material)
```

The key is 32 bytes and is different for each group. Therefore:

- Same group key plus equivalent material can produce the same ID on two
  routers.
- Different group keys produce unrelated IDs.
- A group observer cannot use the shared ID to correlate the device across
  unrelated groups.
- Signal changes produce a different ID; revisions and confidence explain
  changes rather than mutating old observations.

The implementation lives in
`crates/crypto/src/shared_fingerprint.rs`. The matching kestreld material
builder is `networks/kestreld-rs/src/data/shared_fingerprint.rs`. Keep both
formats byte-for-byte compatible when changing the version.

## Key Provisioning

Keys are currently provisioned explicitly. This is intentional: existing group
membership and Iroh transport do not yet provide a secure group key agreement
protocol.

Configure the same key on each participating router:

```sh
sf set-fingerprint-key --group GROUP_ID --key-hex KEY_HEX
```

Keys are stored locally in the `group_fingerprint_keys` SQLite table. They must
not be placed in:

- Signed observations or comments.
- Party-line chat messages.
- Exported public policy files.
- Source control, logs, or CGI output.

Derive a shared ID from canonical material supplied by the kestreld bridge:

```sh
sf derive-fingerprint-id \
  --group GROUP_ID \
  --material-file /tmp/fingerprint.material
```

The current bridge exposes material generation as code, but does not yet
automatically export material from a kestreld identity page or publish the
resulting observation. That handoff is the next integration step.

## Observation Lifecycle

1. `kestreld` observes a device on a local network.
2. `kestreld` creates or updates its private local fingerprint record.
3. The router presents a scored possible match to the administrator.
4. The administrator confirms or rejects the local association.
5. A selected group key derives a shared fingerprint ID from filtered material.
6. The router publishes a signed group observation with confidence and expiry.
7. Other routers ingest the signed observation and add comments or future votes.
8. Each router decides independently whether the evidence is useful locally.

Remote fingerprint evidence must never directly rename a local device, merge a
local identity, change a firewall rule, or alter trust weights.

## UI Integration

The UI should feel unified through same-origin navigation, not binary coupling
or iframes. uhttpd already authenticates both CGI families.

### kestreld to social-firewall

Add to the kestreld dashboard and relevant device pages:

- A Social Firewall summary card showing pending observations, comments, and
  profile effects requiring review.
- Device-page links to the related group fingerprint page.
- An explicit `Share fingerprint evidence` action after local confirmation.
- A clear distinction between local evidence and community evidence.

The identity page should show local signals first, then a separate community
evidence section. It should never imply that a matching shared ID is a proven
identity merge.

### social-firewall to kestreld

Add to social-firewall fingerprint and policy pages:

- `Inspect local device matches` linking to the kestreld identity page.
- `Inspect local router state` for IP/domain targets.
- `Router dashboard` and `Networks` links.
- Route-profile links to local VPN/network status.

These links may carry a target or confirmed local identity reference, but must
not send a remote identity reference that kestreld treats as authoritative.

### Common navigation

Use stable same-origin paths:

```text
/cgi-bin/status
/cgi-bin/network
/cgi-bin/identity
/cgi-bin/sf-policies
/cgi-bin/sf-fingerprint
/cgi-bin/sf-profiles
/cgi-bin/sf-routes
/cgi-bin/sf-partyline
```

The compelling flow is: kestreld notices an unfamiliar device, social-firewall
shows what trusted group members observed and discussed, the user selects a
local profile, and `sf apply --dry-run` shows the exact local effects before
anything is enforced.

## Current Materializers And Safety

- Aggregate deny decisions are materialized into the dedicated
  `inet social_firewall` table.
- DNS policy supports managed dnsmasq output for supported block, redirect, and
  A/AAAA entries.
- Route profiles are stored and validated locally; `sf preview-routes` and
  `sf apply --dry-run` render IP/CIDR route commands but execute none.
- VPN route profiles remain pending until a VPN materializer exists.
- Domain route targets remain pending until a resolver/route correlation path
  exists.
- Shared policies never contain arbitrary shell, UCI, nft, `ip`, WireGuard, or
  resolver commands.
- dnsmasq reloads are OpenWrt-gated by `/etc/openwrt_release` and `/sbin/procd`.
  Controlled non-router overrides are `KESTRELD_ALLOW_SYSTEM_RELOAD=1` and
  `SF_ALLOW_SYSTEM_RELOAD=1`; normal local tests do not invoke host dnsmasq.

## Explicitly Not Implemented Yet

- Automatic group fingerprint-key agreement or rotation.
- Automatic kestreld-to-social-firewall observation export.
- Automatic local identity merge from shared evidence.
- Reputation scoring and anti-Sybil corroboration.
- Full route, mangle, VPN, and generic DNS record materializers.
- Transactional rollback for every materializer.
