## 2026-07-30: run for real on the project's QEMU VM — two real bugs found and fixed

This checklist was executed against the project's existing `test/qemu/`
OpenWrt VM (real `nft` v1.1.6, real `fw4`), driving the crate via a new
`examples/apply_once.rs` test binary (see "Setup" below — that binary
didn't exist before this pass). **Two genuine bugs were found, neither of
which the `FakeCommandRunner` unit tests could have caught, since both are
about real `nft` semantics the fake runner never exercises:**

1. **`flush table` does not clear named set contents** — only chain rules.
   The compiled script's `add table` + `flush table` + a redeclared
   `set X { elements = {...} }` block relied on that redeclaration
   *replacing* a set's elements; empirically, against real `nft`, it
   *merges* into whatever's already there. Result: removing a
   previously-denied IP/CIDR/entry from the policy never actually removed
   it from live enforcement — entries only ever accumulated. Fixed in
   `compile.rs`'s `render_script` by adding an idempotent `add set` (safe
   whether or not the set already exists) followed by an explicit
   `flush set` for each of the four sets, before the table block
   redeclares current elements.
2. **Rollback duplicated every chain rule on every restore.** The
   snapshot captured via `nft -a list table ...` is a *listing*, not a
   from-scratch script; writing it back via `-f` with no `delete`/`add`
   first merges it onto whatever's currently live rather than replacing
   it. A single forced-failure-then-rollback cycle left the `forward`
   chain with 16 rules instead of 8 (every rule duplicated); this
   compounds without bound across repeated failures. Fixed in `lib.rs`'s
   `rollback()` by prepending `delete table` + `add table` to the restore
   script, in the same atomic `-f` transaction, before the captured
   snapshot text.

Both fixes have unit-test regression coverage (`compile.rs`'s
`script_explicitly_flushes_every_set_before_redeclaring_elements`,
`lib.rs`'s `rollback_script_clears_the_table_before_restoring_the_snapshot`)
and were re-verified against the real VM after fixing — 32 unit tests
passing, and every checklist item below marked `[x]` was independently
re-confirmed live against real `nft` output (not just log messages).

**One checklist item could not be verified as originally written**: "the
deny actually blocks traffic" / "priority actually runs before fw4" assume
a genuinely separate client device sending traffic that gets forwarded by
the router. This VM is a single kernel — the simulated WiFi "client"
(`sta-phyN`) is just another interface on the same host, so anything a
local process sends (even sourced from that interface's address) takes the
`OUTPUT` path, never `FORWARD`, regardless of routing tricks; this was
confirmed empirically (routing test traffic via the station interface
produced "Host unreachable", and reasoning through Linux's packet
classification confirms locally-generated packets can never take the
`FORWARD` path no matter what). Genuine `FORWARD`-hook verification would
need either real veth/netns support (this kernel's `ip link add type veth`
returns `RTNETLINK: Not supported` — no netns primitives available) or a
second, physically/virtually distinct host. Everything else on the
checklist — table creation, idempotency, add/remove, CIDR compilation,
invalid-ruleset rejection, apply-failure rollback, health-check-failure
rollback, management-address protection (both compile-time exclusion and
the live chain's accept-first rule), and `fw4 reload` survival — was
verified directly against real `nft` output, which is what actually
proves the crate's core value proposition (valid syntax, real coexistence
with `fw4`, real atomicity/rollback).

# Integration testing on a real OpenWrt VM or disposable router

Everything in this crate's own test suite runs against `FakeCommandRunner`
— no real `nft`, no root, no router. That proves the *logic* (compilation,
idempotency, rollback triggering, protected-destination filtering) but
never proves that the generated nftables text is actually valid syntax
that a real `nft` accepts, coexists with a real `fw4` ruleset, or that the
hook priority actually takes effect before fw4's own rules. Verify that
separately, on real (or QEMU) OpenWrt, before trusting this in production.

**Never run this against a router you depend on for access** — a bug in
the generated ruleset could still drop more than intended even with the
protections in this crate; the whole point of the checklist below is to
prove that isn't happening, on hardware you're willing to physically
recover if it goes wrong (a QEMU VM you can just restart, or a disposable
router with a serial/JTAG recovery path).

This repo already has a QEMU-based OpenWrt VM harness — see the top-level
`test/qemu/` directory and `CONTRIBUTING.md`'s "Testing hierarchy" section
for the existing `setup.sh` / `provision.sh` / `deploy.sh` flow used by
`kestreld`'s own integration tests. This crate doesn't have a `kestreld`-style
deploy script of its own yet; until it does, drive it by hand over SSH as
below.

## Setup

1. Boot the QEMU VM (or have SSH access to a disposable router) with a
   working `fw4`/nftables setup, per the existing `test/qemu/README.md`.
2. Cross-compile `examples/apply_once.rs` (already exists in this crate —
   `cross build --release --target x86_64-unknown-linux-musl --manifest-path
   social-firewall/Cargo.toml -p nft-enforcer --example apply_once`) and copy
   the resulting binary to the VM/router. Usage:
   `apply_once <store.sqlite> <scratch-dir> <apply|dry-run> <revision> [entry...]`,
   where each entry is `<decision>:<kind>:<value>` (e.g. `deny:ip:203.0.113.9`,
   `ask:cidr:198.51.100.0/28`); extra protected addresses beyond the
   built-in loopback/link-local defaults come from `SF_PROTECT_IPS`
   (comma-separated addresses/CIDRs). See the file's own doc comment for
   details.
3. Confirm `nft list ruleset` on the VM shows a real `fw4`-managed
   ruleset already in place (i.e. this isn't a from-scratch nftables setup)
   — the whole point is proving coexistence, not proving nftables itself
   works on an empty ruleset.

## Checklist

- [x] **Fresh apply creates the table.** Verified: `nft list table inet
      social_firewall` showed exactly the expected 4 sets and `forward`
      chain; `nft list table inet fw4` diffed identical before/after
      except expected counter/lease-expiry drift (zero structural change).
- [ ] **The deny actually blocks traffic.** Not verifiable on this VM as
      written — see "could not be verified" note above. Needs a second
      real/virtual host, or veth/netns support this kernel lacks.
- [x] **Reapplying the identical policy is a true no-op.** Verified:
      `nft -a list table` handle-line output was byte-identical
      before/after a same-policy reapply (`ApplyResult::NoChange`).
- [x] **Adding/removing entries changes only what's expected.** Verified —
      this is where the first real bug (set-flush) was caught: initially
      removing an IP left it in the live set anyway. After the fix,
      confirmed add-two/remove-one/keep-one behaves correctly against
      real `nft`.
- [x] **CIDR ranges compile and enforce correctly.** Verified: a `/28`
      deny and an IPv6 `Ask` (quarantine) both appeared correctly in their
      respective live sets with the correct interval-set syntax.
- [ ] **Priority actually runs before fw4.** Not verifiable on this VM as
      written — same single-kernel limitation as the traffic-blocking
      item above.
- [x] **A real invalid ruleset is rejected by `nft --check`.** Verified:
      a hand-corrupted script was rejected by real `nft --check` with a
      syntax error and exit 1; live table state was confirmed byte-for-byte
      unchanged (handle-line checksum match) afterward.
- [x] **A forced apply failure rolls back cleanly.** Verified — this is
      where the second real bug (rollback duplicating all chain rules)
      was caught. After the fix: a wrapper-simulated `nft -f` failure on
      the real apply call triggered a rollback that restored the exact
      pre-attempt ruleset (8 rules, no duplication, correct elements).
- [x] **Management access survives an adversarial policy.** Verified
      against a real management-relevant address (the VM's LAN gateway,
      `192.168.1.1`, via `SF_PROTECT_IPS`): a `Deny` entry targeting it
      never appeared in the live `deny_v4` set, and an explicit
      `ip daddr 192.168.1.1 accept` rule was present and ordered first in
      the live chain. (Note: for the router's *own* address specifically,
      this protection is defense-in-depth rather than load-bearing — a
      `forward`-hook rule can never affect traffic destined to a local
      address in the first place, since that's always `INPUT`-hook
      traffic at the kernel level, regardless of this crate. The
      meaningful real-world case this protects is a *downstream*
      management-relevant host reached *through* the router.)
- [x] **A forced health-check failure rolls back cleanly.** Verified
      (added to this pass, beyond the original checklist item list): a
      wrapper made the post-apply `nft -a list table` health-check call
      fail specifically (while the pre-apply snapshot's identical-looking
      call succeeded) — confirmed `ApplyResult::Failed` with a successful
      rollback restoring the exact pre-attempt state, no duplication,
      after the rollback fix.
- [x] **Router reboot / fw4 reload survives.** Verified: ran
      `/etc/init.d/firewall reload` for real; `inet social_firewall`'s
      element-line output was checksum-identical before/after, and
      `inet fw4` remained intact.

## Known gaps this checklist does not cover

- **DNS-derived (hostname) enforcement** is explicitly out of scope for
  this pass — `Destination::Hostname` is recorded but never enforced, so
  there's nothing to verify here yet.
- **Concurrent appliers**: this crate assumes one `NftablesController`
  applying at a time (matches its `state-store` caller's existing
  single-writer assumption). If kestreld's own multi-process concurrency
  model (see its SQLite migration work) ever needs to drive this crate
  from more than one process at once, that needs its own locking story —
  not exercised here.
