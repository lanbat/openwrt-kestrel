#!/bin/sh
# social-firewall/install.sh — sets up the cron-driven `sf apply` reconciliation
# loop. Cron-only, no procd service (see split-routing/install.sh for the
# precedent this mirrors) — social-firewall is a genuinely optional,
# independently installable/removable package: it never touches kestreld's
# own cron entries, config, or state, and vice versa.
#
# Usage:
#   sh social-firewall/install.sh          — install/update
#   sh social-firewall/install.sh remove   — remove the cron entry and the
#                                             live `inet social_firewall`
#                                             nftables table; leaves the
#                                             config file and SQLite state
#                                             database in place
#   sh social-firewall/install.sh remove --purge — also delete the base
#                                             directory (config + database)
set -eu

BASE_DIR=/etc/kestrel/social-firewall
CONFIG="$BASE_DIR/config"
NFT_SCRATCH_DIR="$BASE_DIR/nft"
STORE="$BASE_DIR/social-firewall.sqlite"
CRONTAB=/etc/crontabs/root
CRON_TAG="social-firewall-apply"

if [ "${1:-}" = "remove" ]; then
    sed -i "/# ${CRON_TAG}\$/d" "$CRONTAB" 2>/dev/null || true
    /etc/init.d/cron restart 2>/dev/null || true
    nft delete table inet social_firewall 2>/dev/null || true
    if [ "${2:-}" = "--purge" ]; then
        rm -rf "$BASE_DIR"
        echo "Removed cron entry, live nftables table, and $BASE_DIR."
    else
        echo "Removed cron entry and live nftables table. $BASE_DIR (config + database) left in place — pass --purge to also delete it."
    fi
    exit 0
fi

if [ ! -x /usr/bin/sf ]; then
    echo "WARNING: /usr/bin/sf not found — install the social-firewall package first (see release/openwrt/social-firewall/Makefile). Skipping cron setup." >&2
    exit 0
fi

mkdir -p "$BASE_DIR" "$NFT_SCRATCH_DIR"

# ── config ───────────────────────────────────────────────────────────────────
# Hand-edited by the admin after install — never overwritten once present,
# same convention as split-routing's own config/vpn-*.conf seeding.

[ -f "$CONFIG" ] || cat >"$CONFIG" <<'EOF'
# social-firewall settings, read by the cron-driven `sf apply` run.

# Addresses/CIDR ranges that must never be denied/quarantined by an
# imported opinion, in addition to the loopback/link-local defaults
# nft-enforcer always protects — typically this router's own LAN/management
# address(es). Space-separated.
PROTECT_IPS=""

# Combined allow/deny weight required on one side, with nothing on the
# other, for trust-weighted aggregation to auto-decide (see policy-engine).
THRESHOLD=1.0
EOF

# ── cron ─────────────────────────────────────────────────────────────────────
# Idempotent tag-based upsert — same pattern networks/install.sh's
# `_cron_set` and split-routing/install.sh's own cron line use.

touch "$CRONTAB"
sed -i "/# ${CRON_TAG}\$/d" "$CRONTAB"
cat >>"$CRONTAB" <<EOF
*/5 * * * * . $CONFIG; /usr/bin/sf --db $STORE apply --threshold "\$THRESHOLD" \$(for ip in \$PROTECT_IPS; do printf -- '--protect-ip %s ' "\$ip"; done) --scratch-dir $NFT_SCRATCH_DIR >/tmp/social-firewall-apply.log 2>&1  # ${CRON_TAG}
EOF
/etc/init.d/cron restart 2>/dev/null || true

echo "Installed."
echo "  $CONFIG"
echo "  $STORE"
echo "  Cron: $(grep "$CRON_TAG" "$CRONTAB")"
