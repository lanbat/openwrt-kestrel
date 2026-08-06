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
and exposes the party-line chat at `/cgi-bin/sf-chat`.

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

The browser chat is the easiest way to talk:

```text
http://ROUTER_IP/cgi-bin/sf-chat
```

Messages typed without a leading slash are published to the selected group.
The selected group's topic is shown above the transcript.
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
