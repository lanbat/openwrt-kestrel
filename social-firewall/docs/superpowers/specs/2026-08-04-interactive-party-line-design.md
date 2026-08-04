# Interactive party-line: web chat, commands, and notifications

## Context

The read-only dashboard (`crates/dashboard`) intentionally has zero
mutation capability — its entire security argument is "there's no
CSRF/auth surface to design because there's nothing to submit." This
feature is a deliberate, explicit departure from that: a web-based,
terminal-styled chat interface where an operator can read party-line
activity, see notifications for anything awaiting a decision, and issue
the same commands the CLI already supports — directly from a browser.

This is scoped separately from the read-only dashboard (which stays
exactly as it is) and separately from the P2P transport spec (which is
node-to-node statement delivery; this is operator-to-router control).

## Goals

- A web-served, monospace/terminal-styled chat view per party line
  (including the new "self" party line — see below).
- Commands typed in the chat box execute the same logic as the
  equivalent `sf` CLI subcommand — no second implementation of any
  command's behavior.
- Every notification that currently requires an operator to run a
  `list-pending-*` command has a home in some party line, with no
  exceptions.
- Optional push of new notifications to an external `ntfy` topic.

## Non-goals

- Not a general chat/social product — this is a router admin surface
  that happens to look like IRC, for an audience already comfortable
  with the CLI.
- Not real-time/websocket push in this phase — a page reload or short
  polling interval is enough for a low-traffic router admin panel,
  consistent with "no async runtime, no heavy framework" already
  established for the read-only dashboard.
- The existing read-only dashboard (`sf serve-dashboard`, `tiny_http`)
  is untouched — it keeps working standalone, with zero mutation
  surface, exactly as today. This is a second, separate, higher-privilege
  surface, not a replacement.

## Architecture

### Serving: uhttpd + CGI, not a new listener

Confirmed against `kestreld-rs/src/cgi.rs` and its `install.sh`
deployment (`ln -sf /usr/bin/kestreld "/www/cgi-bin/${_ep}"`,
`uci set uhttpd.main.cgi_prefix=/cgi-bin`) — this is a real, already-
deployed pattern on this exact router family, not a new one being
introduced. `sf` gains the same shape:

```rust
pub fn is_cgi() -> bool { std::env::var("REQUEST_METHOD").is_ok() }
pub fn run_cgi() { /* dispatch on SCRIPT_NAME + REQUEST_METHOD, same as kestreld's cgi.rs */ }
```

checked at the very top of `main()`, before clap parsing. Deployment
mirrors kestreld's exactly: `install.sh` symlinks `/www/cgi-bin/sf-chat`
(and friends) to the `sf` binary and idempotently ensures
`uhttpd.main.cgi_prefix=/cgi-bin`, matching the existing
`if ! uci -q get uhttpd.main.cgi_prefix` guard kestreld's installer
already uses. No new persistent process, no new port, no new TLS
story — inherits whatever uhttpd is already configured with.

**Trust boundary**: LAN-reachability, the same boundary kestreld already
accepted for its own mutation endpoints (`approve-join`,
`rotate-password`) and the same one this whole project already uses for
CLI access ("whoever can reach this already has the relevant
privilege"). No new app-level auth is being invented here — this
matches existing, accepted precedent rather than introducing a new
security model to review.

### Commands: reuse the CLI's own parser, not a second grammar

The chat's command box feeds typed text (e.g.
`/approve-group-join --group <id> --requester <ref> --sequence 0
--voting`) through `sf`'s existing clap `Command::parse_from`, tokenized
the same way a shell would split it — dispatching to the *exact* same
match arms `main()` already has. A message with no leading `/` is just a
normal `publish-party-line` post. This means every command already
documented in `sf --help` works in chat for free, and any new CLI
subcommand added later works in chat without extra effort — there is
deliberately no second command surface to keep in sync.

### Notifications: every one lands in *some* party line, no exceptions

Group-scoped notifications (join requests, votes needing attention) post
into that group's own party line — this is free, the mechanism already
exists (`PartyLineMessage` + the join/leave log built earlier this
session).

For notifications with no group at all (tunnel connection requests,
tunnel service requests) — **every identity automatically gets one
implicit "self" group**, created at `init-identity` time: owner = self,
members = `[self]`. Nothing new in the data model — it's the exact same
`Group` + `PartyLineMessage` machinery, just a group of one. Anything
without a natural group destination posts there instead. This closes the
gap without inventing a second notification mechanism alongside the
per-group one.

A background pass (piggybacking on the existing `sf sync-tunnels`
cron-driven reconciliation, or a small sibling to it) is responsible for
noticing new pending items and posting the corresponding notification —
idempotent, the same "don't re-notify for something already surfaced"
discipline `sync_tunnels` already applies to its own auto-behaviors.

### Optional ntfy push

A single global setting (topic URL + on/off — not per-group, to keep
this simple for v1): when the background notifier posts a new
notification to any party line, it also, optionally, POSTs a short
summary to the configured `ntfy` topic. Self-hosted `ntfy` servers are
the primary case, matching this project's own self-hosted ethos — the
topic URL is just a config value, no assumption of `ntfy.sh` specifically.
Only a short summary leaves the router (e.g. "bob wants to join
neighborhood watch"), never the full signed statement payload — keeps
the external egress minimal and consistent with how carefully this
project treats what leaves the router elsewhere (e.g. `Restricted`
visibility, sealed exports).

### Styling

Monospace, IRC/mIRC-styled rendering — CSS `font-family` stack aiming
for a Fixedsys-like bitmap-terminal look with real Unicode coverage
(e.g. `"Fixedsys Excelsior", "Terminus", ui-monospace, monospace`, plus
a bundled web-font fallback if a suitable open-licensed one is found
during implementation). Dark terminal-style palette by default.

## Data flow

1. Operator loads `/cgi-bin/sf-chat?group=<id>` (or the "self" group by
   default) → CGI GET renders the merged message/join-leave/notification
   timeline for that party line, using the exact same
   `list_party_line_messages` + `list_group_membership_events` merge
   already built for the CLI's `list-party-line`.
2. Operator types a command or message, submits → CGI POST → either
   dispatches through `Command::parse_from` (a `/`-prefixed command) or
   calls `publish-party-line`'s existing logic (a plain message) →
   redirect/refresh back to the same view.
3. Background notifier (cron-driven) detects new pending items → posts a
   synthesized party-line entry to the relevant group (or "self") →
   optionally POSTs to `ntfy`.

## Error handling

- A malformed or unauthorized command (e.g. approving a join you're not
  an owner/admin of) surfaces the exact same error the CLI would print,
  rendered back into the chat view rather than silently dropped.
- `ntfy` delivery failure is logged and never blocks the party-line post
  itself succeeding — the router's own record is always the source of
  truth, `ntfy` is a best-effort convenience notification only.

## Testing

- `run_cgi`'s dispatch table: unit tests per `(SCRIPT_NAME, METHOD)`
  pair, mirroring kestreld's own CGI test shape if one exists there.
- Command-box parsing: a typed string round-trips through
  `Command::parse_from` correctly, including a malformed command
  producing a clean error rather than a panic.
- "Self" group: created automatically at `init-identity`, a tunnel
  request notification lands there, confirmed via a CLI-level
  integration test.
- ntfy: a fake HTTP sink in tests confirms the summary sent (and that
  the full statement payload is never included), plus a test confirming
  a simulated `ntfy` failure never blocks the underlying notification
  from being recorded.

## Future work (explicitly deferred)

- Real-time push (websocket/long-poll) instead of reload/poll, if
  request volume ever justifies it.
- Per-group ntfy topic configuration instead of one global setting.
- Folding the read-only dashboard's tables into this same surface, if a
  single unified page ever becomes worth the added complexity.
