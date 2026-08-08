# social-firewall

`social-firewall` (`sf`) is an optional, decentralized policy tool for
OpenWrt. Routers publish signed opinions about domains and IP addresses,
follow other routers with trust weights, and apply the resulting decision in
the separate `inet social_firewall` nftables table.

The identity and signature are the security boundary. Nicknames, group names,
and follow labels are for people; they never replace the underlying IDs.

## Install

Install the `social-firewall` package, then run the installer on the router:

```sh
sh /root/openwrt-kestrel/social-firewall/install.sh
```

This creates the SQLite store at
`/etc/kestrel/social-firewall/social-firewall.sqlite`, installs the cron jobs,
and exposes the partyline at `/cgi-bin/sf-partyline` with `/cgi-bin/sf-chat`
retained as a compatibility alias.

It also publishes a static SPA shell at `/kestrel-ui/`. The shell is served
directly by uhttpd and currently links to the existing CGI surfaces; see
`docs/spa-migration.md` for the migration boundary.

### Optional Iroh Listener

The Iroh listener is installed as a disabled-by-default procd service. Enable
it when this router should receive signed synchronization envelopes:

```sh
uci set social-firewall.main.enabled='1'
uci commit social-firewall
/etc/init.d/social-firewall enable
/etc/init.d/social-firewall start
```

The listener accepts peer envelopes only; it does not expose the browser
partyline or an IRC service. The partyline remains available through the local
uhttpd CGI endpoints.

### Optional LAN IRCv3 Gateway

The IRC gateway is disabled by default and refuses wildcard listen addresses.
Configure a specific trusted-LAN address, then enable it:

```sh
uci set sf-ircd.main.listen_addr='192.168.1.1:6697'
uci set sf-ircd.main.tls_cert='/etc/uhttpd.crt'
uci set sf-ircd.main.tls_key='/etc/uhttpd.key'
uci set sf-ircd.main.enabled='1'
uci commit sf-ircd
/etc/init.d/sf-ircd enable
/etc/init.d/sf-ircd start
```

It supports IRC registration, `CAP LS 302`, `message-tags`, `server-time`,
`JOIN`, `PART`, `NAMES`, `LIST`, `WHO`, `WHOIS`, `PRIVMSG`, `NOTICE`,
`TOPIC`, `INVITE`, and moderated-channel `MODE`. Channels are existing
social-firewall groups named `#sf-<group-id>`. IRC access is local-only; Iroh and Reticulum
 never expose this listener. Newly ingested remote party-line messages are
 also pushed to already-connected clients in the matching channel.

Native IRC `INVITE` accepts a social-firewall user ID and publishes a signed
non-voting group invitation:

```text
INVITE FEDERATION_ID/LOCAL_ID #sf-GROUP_ID
```

The `/sf` command namespace exposes signed group, policy, opinion, vote,
synchronization, tunnel, and guarded local-apply operations without spawning a
shell command. Local apply is dry-run by default and requires explicit
confirmation for mutation.

The service creates one `fw4` accept rule for the configured `firewall_zone`
(default `lan`) and removes it when stopped. Other OpenWrt zones are not
permitted to reach the IRC port.

TLS defaults to the local uhttpd certificate and key. Replace those paths with
ACME-managed files when using a public DNS name; the certificate hostname must
match the name used by IRC clients.

To require Authentik OIDC authentication, configure its introspection endpoint
and a confidential client secret file. This enables mandatory IRCv3 SASL
`OAUTHBEARER` authentication:

```sh
uci set sf-ircd.main.oidc_introspection_url='https://auth.example.net/application/o/introspect/'
uci set sf-ircd.main.oidc_client_id='client-id'
uci set sf-ircd.main.oidc_client_secret_file='/etc/kestrel/authentik-irc-client-secret'
uci set sf-ircd.main.oidc_ca_file='/etc/ssl/certs/authentik-ca.pem'
uci set sf-ircd.main.oidc_issuer='https://auth.example.net'
uci set sf-ircd.main.oidc_audience='client-id'
uci set sf-ircd.main.oidc_required_group='router-users'
uci set sf-ircd.main.oidc_write_entitlement='router:write'
uci set sf-ircd.main.oidc_operator_entitlement='router:write'
uci commit sf-ircd
```

The secret file must be readable only by root. Authentik token introspection is
performed over HTTPS; inactive, issuer-mismatched, or audience-mismatched
tokens are rejected before IRC registration completes.

When OIDC is enabled, `oidc_write_entitlement` controls `PRIVMSG`/`NOTICE`,
while `oidc_operator_entitlement` controls `TOPIC` and channel `MODE` changes.

### Optional Reticulum Bridge

Reticulum is an optional control-plane fallback when Iroh delivery fails or an
Iroh address is not available. The package installs a native Rust bridge binary
and creates a disabled-by-default `/etc/config/reticulum-bridge`. Configure at least one
TCP or UDP interface, then enable and start the service:

```sh
uci set reticulum-bridge.main.enabled='1'
uci commit reticulum-bridge
/etc/init.d/reticulum-bridge enable
/etc/init.d/reticulum-bridge start
```

The bridge uses only `/run/kestrel/reticulum.sock` for Kestrel control. Its
Reticulum TCP/UDP interface is configured separately through UCI. Configure a
peer's 16-byte Reticulum destination hash with:

```sh
sf set-follow-reticulum-address \
  --federation FEDERATION_ID --user LOCAL_ID --address DESTINATION_HASH
```

Application envelopes remain signed and are still checked by the Rust process.
Enabling the bridge also starts the Reticulum receive listener, which accepts
only addresses configured for followed peers. See
`docs/reticulum-bridge-protocol.md` for the socket contract.

Building the workspace with the Reticulum bridge also requires a host
`protoc` binary because the pinned Reticulum-rs dependency generates its
protocol bindings during compilation. The released OpenWrt package contains
the already-built bridge binary and does not need Python RNS.

Run the local two-node Reticulum integration test explicitly:

```sh
PROTOC=/path/to/protoc cargo test -p reticulum-bridge --test two_node -- --ignored
```

## First Run

Create the router identity once:

```sh
sf init-identity --display-name demo
sf set-federation-name --name home
```

Common short forms are available too: `sf init`, `sf nick`, `sf groups`,
`sf follows`, `sf follow`, `sf opinion`, `sf check`, and `sf enforce`.

The display name is a nickname, not the identity. The full federation and
local IDs printed by `init-identity` are the canonical values to share with a
peer. In chat, the same identity is shown compactly, for example:

```text
demo (5779adc7@home): hello
```

To change or clear the local nickname later:

```sh
sf set-identity-name --name router
sf set-identity-name
```

## Following A Router

`add-follow` means “accept this router's signed statements as an input to my
local policy.” It does not give that router control of the local firewall.

```sh
sf add-follow \
  --federation FEDERATION_ID \
  --user LOCAL_ID \
  --name alice \
  --allow-weight 1.0 \
  --deny-weight 1.0
```

The `--name` value is a private address-book label. It is safe to reuse the
same label in different federations. Change it without changing trust:

```sh
sf set-follow-name --federation FEDERATION_ID --user LOCAL_ID --name alice
```

## Opinions And Enforcement

Publish a signed opinion and export it for delivery when Iroh is unavailable:

```sh
sf publish-opinion \
  --target-kind domain \
  --target-value ads.example \
  --stance deny \
  --reason-code malware \
  --note "known advertising host" \
  --out /tmp/opinion.json
```

Ingest a file received from another router:

```sh
sf ingest-opinion --file /tmp/opinion.json
```

Preview or apply the aggregate policy:

```sh
sf evaluate-target --target-kind domain --target-value ads.example
sf apply --dry-run
sf apply
```

The installer runs `sf apply` from cron. A decision of `allow`, `ask`, or no
decision does not create a deny rule; only an enforced deny is placed in the
social-firewall nftables table.

## Groups And Party-Line Chat

Create a group and note its ID from the command output:

```sh
sf create-group --name "Neighborhood Watch" --description "trusted routers"
sf list-groups
sf set-group-topic --group "Neighborhood Watch" --topic "trusted routers and review notes"
```

The browser partyline is the easiest way to talk:

```text
http://ROUTER_IP/cgi-bin/sf-partyline
```

Messages typed without a leading slash are published to the selected group.
The selected group's topic is shown above the transcript.
Party-line messages are signed and fanned out to current group members; Iroh
delivery falls back to configured Reticulum addresses and is retried through
the outbox, while `sync`/`sync-group` catch up peers
that were offline. IRC-style `/me`, `/nick`, `/topic`, `/mode +m`, `/mode -m`,
and `/mode +v USER` or `/mode -v USER` actions publish visible system events as well as updating
the signed group state where applicable.
Commands beginning with `/` are passed to the real `sf` CLI, so the browser
does not implement a second command language:

```text
hello everyone
/say hello everyone
/groups
/follows
/history
/help
/list-groups
/approve-group-join --group GROUP_ID --requester USER_ID --sequence 0
```

The chat automatically refreshes only while idle. It never reloads while the
message prompt is focused or contains text. Use the `refresh` button to force
an update.

For scripts or file-based workflows, the equivalent CLI commands are:

```sh
sf publish-party-line \
  --group "Neighborhood Watch" \
  --body "hello everyone"
sf list-party-line --group "Neighborhood Watch"
```

If a followed peer has an Iroh node ID configured, `sf sync` can deliver
eligible statements directly. Otherwise commands with `--out` or `--out-dir`
produce files for manual transfer. Both paths ingest the same signed payloads.

## Pending Decisions

The notifier surfaces pending group joins and tunnel requests in the implicit
self group:

```sh
sf notify
sf list-party-line --group SELF_GROUP_ID
```

The installer runs this every five minutes. Optional ntfy delivery can be
configured with a plain HTTP topic on the LAN:

```sh
sf set-ntfy-topic --url http://ntfy.lan/social-firewall
```

## Shared Policy Roadmap

The long-term replication model is a signed, versioned shared policy that
routers can review through group votes and trust-weighted opinions. Accepted
entries will be materialized locally as firewall blocks, validated route/VPN
profile selections, DNS filters, redirects, or typed DNS record overrides.
Users will select these through local profiles and collections. DNS overrides
are advertised policy entries, so they can be voted on, expired, and audited
like routes and ACLs.
The same model will support group-scoped device fingerprints and comments.
Nodes may belong to multiple groups; fingerprint evidence, comments, votes,
and trust remain scoped to the group where they were shared. Collections will
also carry typed limits for connections, bandwidth, sessions, rates, DNS, and
tunnel usage, subject to each router's local enforcement capabilities.
Reputation will likewise be scoped by group, capability, role, and time window;
it will help discovery and review, but will not silently alter enforcement
weights.
The design and implementation phases are tracked in
`docs/superpowers/plans/2026-08-05-shared-policy-replication.md`.

The detailed fingerprint, key, UI, and materializer contract is documented in
`docs/fingerprints-and-ui.md`.

Shared fingerprint keys are currently provisioned explicitly between routers;
they are stored in the local SQLite database and are never included in signed
observations. Configure the same 32-byte key on each member of a group, then
derive an ID from canonical material generated by the kestreld bridge:

```sh
sf set-fingerprint-key --group GROUP_ID --key-hex KEY_HEX
sf derive-fingerprint-id --group GROUP_ID --material-file /tmp/fingerprint.material
```

This is a deliberate bootstrap workflow, not automatic key distribution. Do
not put the key in a signed payload, chat message, or repository. The current
implementation derives IDs and validates material but does not merge local
identities or automatically publish observations.

The current release only automatically materializes aggregate `deny`
decisions into the local social-firewall nftables table. Routing and DNS
policy replication are planned, not silently implied by existing group votes.

## Useful Inspection Commands

```sh
sf list-follows
sf list-groups
sf list-tunnels
sf list-pending-group-joins --group GROUP_ID
sf list-pending-tunnel-requests
sf list-party-line --group GROUP_ID
sf --help
```

The SQLite database is local state. Back it up before experimenting with
configuration changes:

```sh
cp /etc/kestrel/social-firewall/social-firewall.sqlite /tmp/social-firewall.sqlite.backup
```
