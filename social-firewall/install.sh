#!/bin/sh
# social-firewall/install.sh — sets up the cron-driven `sf apply` reconciliation
# loop and optional procd listeners. social-firewall is a genuinely optional,
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
NOTIFY_CRON_TAG="social-firewall-notify"
SYNC_CRON_TAG="social-firewall-sync"
UI_DIR=/www/kestrel-ui
BRIDGE_INIT=/etc/init.d/reticulum-bridge
BRIDGE_CONFIG=/etc/config/reticulum-bridge
LISTENER_INIT=/etc/init.d/social-firewall
LISTENER_CONFIG=/etc/config/social-firewall
IRC_INIT=/etc/init.d/sf-ircd
IRC_CONFIG=/etc/config/sf-ircd

if [ "${1:-}" = "remove" ]; then
    "$IRC_INIT" stop 2>/dev/null || true
    "$IRC_INIT" disable 2>/dev/null || true
    "$LISTENER_INIT" stop 2>/dev/null || true
    "$LISTENER_INIT" disable 2>/dev/null || true
    "$BRIDGE_INIT" stop 2>/dev/null || true
    "$BRIDGE_INIT" disable 2>/dev/null || true
    rm -f "$IRC_INIT" "$IRC_CONFIG" "$LISTENER_INIT" "$LISTENER_CONFIG" "$BRIDGE_INIT" "$BRIDGE_CONFIG"
    sed -i "/# ${CRON_TAG}\$/d" "$CRONTAB" 2>/dev/null || true
    sed -i "/# ${NOTIFY_CRON_TAG}\$/d" "$CRONTAB" 2>/dev/null || true
    sed -i "/# ${SYNC_CRON_TAG}\$/d" "$CRONTAB" 2>/dev/null || true
    /etc/init.d/cron restart 2>/dev/null || true
    nft delete table inet social_firewall 2>/dev/null || true
    rm -rf "$UI_DIR"
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

mkdir -p /etc/config
# The Iroh listener is optional and remains disabled until an administrator
# enables it.
[ -f "$LISTENER_CONFIG" ] || cp "$(dirname "$0")/social-firewall.config" "$LISTENER_CONFIG"
cp "$(dirname "$0")/social-firewall.init" "$LISTENER_INIT"
chmod 0755 "$LISTENER_INIT"
[ -f "$IRC_CONFIG" ] || cp "$(dirname "$0")/sf-ircd.config" "$IRC_CONFIG"
cp "$(dirname "$0")/sf-ircd.init" "$IRC_INIT"
chmod 0755 "$IRC_INIT"

# The bridge is optional and remains disabled until an administrator enables it.
if [ ! -x /usr/bin/kestrel-reticulum-bridge ]; then
    echo "WARNING: /usr/bin/kestrel-reticulum-bridge not found — install the bridge binary to enable Reticulum." >&2
fi
cp "$(dirname "$0")/reticulum-bridge.init" "$BRIDGE_INIT"
chmod 0755 "$BRIDGE_INIT"
[ -f "$BRIDGE_CONFIG" ] || cp "$(dirname "$0")/reticulum-bridge.config" "$BRIDGE_CONFIG"

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
sed -i "/# ${NOTIFY_CRON_TAG}\$/d" "$CRONTAB"
sed -i "/# ${SYNC_CRON_TAG}\$/d" "$CRONTAB"
cat >>"$CRONTAB" <<EOF
*/5 * * * * . $CONFIG; /usr/bin/sf --db $STORE apply --threshold "\$THRESHOLD" \$(for ip in \$PROTECT_IPS; do printf -- '--protect-ip %s ' "\$ip"; done) --scratch-dir $NFT_SCRATCH_DIR >/tmp/social-firewall-apply.log 2>&1  # ${CRON_TAG}
*/5 * * * * /usr/bin/sf --db $STORE notify >/tmp/social-firewall-notify.log 2>&1  # ${NOTIFY_CRON_TAG}
* * * * * /usr/bin/sf --db $STORE sync >/tmp/social-firewall-sync.log 2>&1  # ${SYNC_CRON_TAG}
EOF
/etc/init.d/cron restart 2>/dev/null || true

# uhttpd runs the party-line chat as a fresh CGI process per request.
mkdir -p /www/cgi-bin
mkdir -p "$UI_DIR"
cp "$(dirname "$0")/ui/index.html" "$UI_DIR/index.html"
cp "$(dirname "$0")/ui/app.js" "$UI_DIR/app.js"
cp "$(dirname "$0")/ui/styles.css" "$UI_DIR/styles.css"
ln -sf /usr/bin/sf /www/cgi-bin/sf-chat
ln -sf /usr/bin/sf /www/cgi-bin/sf-partyline
ln -sf /usr/bin/sf /www/cgi-bin/sf-groups
ln -sf /usr/bin/sf /www/cgi-bin/sf-chat-font
ln -sf /usr/bin/sf /www/cgi-bin/sf-policies
ln -sf /usr/bin/sf /www/cgi-bin/sf-policy-vote
ln -sf /usr/bin/sf /www/cgi-bin/sf-policy-explain
ln -sf /usr/bin/sf /www/cgi-bin/sf-fingerprint
ln -sf /usr/bin/sf /www/cgi-bin/sf-profiles
ln -sf /usr/bin/sf /www/cgi-bin/sf-routes
if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
    uci set uhttpd.main.cgi_prefix=/cgi-bin
    uci commit uhttpd
    /etc/init.d/uhttpd restart 2>/dev/null || true
fi

echo "Installed."
echo "  $CONFIG"
echo "  $STORE"
echo "  Iroh listener: $LISTENER_CONFIG (disabled by default)"
echo "  IRCv3 listener: $IRC_CONFIG (disabled by default; bind a trusted LAN address before enabling)"
echo "  Reticulum bridge: $BRIDGE_CONFIG (disabled by default)"
echo "  Cron: $(grep "$CRON_TAG" "$CRONTAB")"
echo "  Partyline: http://<router-ip>/cgi-bin/sf-partyline"
echo "  SPA shell: http://<router-ip>/kestrel-ui/"
