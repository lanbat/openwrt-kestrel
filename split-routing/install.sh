#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LISTS_DIR=/etc/split-routing
CONFIG="$LISTS_DIR/config"
STATE="$LISTS_DIR/state"
CRONTAB=/etc/crontabs/root
HOTPLUG=/etc/hotplug.d/iface/99-mullvad-routing

write_script() { cat >"$1"; chmod 0755 "$1"; }

# ── config ─────────────────────────────────────────────────────────────────────

mkdir -p "$LISTS_DIR"
[ -f "$CONFIG" ] || cat >"$CONFIG" <<'EOF'
# Network interface for the VPN tunnel (run: ip link show)
VPN_IFACE=mv

# Policy routing table number for VPN traffic.
# Change if another tool (mwan3, vpn-policy-routing) already uses table 100.
ROUTE_TABLE=100

# Firewall mark applied to packets destined for the VPN sets.
# Change if another tool (mwan3, OpenVPN) already uses mark 0x1.
FWMARK=0x1

# How long dnsmasq-populated IPs stay in the nft sets before expiring.
# Shorter values mean removed domains self-clean sooner; longer means less DNS churn.
DNS_TIMEOUT=24h

# Route IPv6 traffic through the VPN as well (yes/no).
# Set to no if your VPN endpoint does not carry IPv6 — otherwise marked IPv6
# traffic will be silently dropped rather than routed.
ROUTE_IPV6=yes

# Categories for the dns mechanism (lazy population via dnsmasq nftset directive).
# Each name needs a matching dns() call in /usr/sbin/update-routing-sets and a
# local-dns-<name>.txt file in /etc/split-routing/.
DNS_CATS="torrentsites pornsites sites"

# Categories for the resolve mechanism (nslookup at update time, interval sets).
# Each name needs a matching resolve() call in /usr/sbin/update-routing-sets and a
# local-resolve-<name>.txt file in /etc/split-routing/.
RESOLVE_CATS="torrenttrackers sites"
EOF
. "$CONFIG"

# Migrate existing configs that predate DNS_CATS/RESOLVE_CATS.
if [ -z "${DNS_CATS:-}" ]; then
  DNS_CATS="torrentsites pornsites sites"
  printf '\nDNS_CATS="%s"\n' "$DNS_CATS" >>"$CONFIG"
fi
if [ -z "${RESOLVE_CATS:-}" ]; then
  RESOLVE_CATS="torrenttrackers sites"
  printf '\nRESOLVE_CATS="%s"\n' "$RESOLVE_CATS" >>"$CONFIG"
fi

# Derive nft set names and local file names from categories.
DNSMASQ_SETS=""; for c in $DNS_CATS;     do DNSMASQ_SETS="$DNSMASQ_SETS dns_$c";     done
INTERVAL_SETS=""; for c in $RESOLVE_CATS; do INTERVAL_SETS="$INTERVAL_SETS resolve_$c"; done

LOCAL_FILES=""
for c in $DNS_CATS;     do LOCAL_FILES="$LOCAL_FILES local-dns-${c}.txt";     done
for c in $RESOLVE_CATS; do LOCAL_FILES="$LOCAL_FILES local-resolve-${c}.txt"; done

# ── nft-resolve (resolve domains → nft interval sets) ──────────────────────────

cp "$SCRIPT_DIR/nft-resolve" /usr/sbin/nft-resolve
chmod 0755 /usr/sbin/nft-resolve

# Remove old script names from previous installs.
rm -f /usr/sbin/update-nft-blocklist /usr/sbin/nftset-from-list /usr/sbin/update-dns-nftset

# ── update-routing-sets (user-editable template — created once, never overwritten) ──

if [ ! -f /usr/sbin/update-routing-sets ]; then
  write_script /usr/sbin/update-routing-sets <<'EOF'
#!/bin/sh
# Edit this file to add, remove, or change source URLs for each category.
# Category names must match DNS_CATS and RESOLVE_CATS in /etc/split-routing/config.
# After changing categories, re-run install.sh so nft sets and state are updated.

# Convert a domain list (multiple formats) to dnsmasq nftset= directives.
nftset_from_list() {
  awk -v rule="$1" '
    /^\|\|/ { sub(/^\|\|/,""); sub(/\^.*/,""); if ($0!="") print "nftset=/"$0"/"rule; next }
    /^[[:space:]]*(#|!|$)/ { next }
    { sub(/[[:space:]].*/,""); sub(/\r/,""); if ($0!="") print "nftset=/"$0"/"rule }
  '
}

# Fetch domain lists, write a dnsmasq nftset config, and reload dnsmasq.
dns() {
  cat=$1; shift
  echo "==> dns $cat"
  local conf="/etc/dnsmasq.d/${cat}.conf"
  local rule="4#inet#fw4#dns_${cat}4,6#inet#fw4#dns_${cat}6"
  local local_file="/etc/split-routing/local-dns-${cat}.txt"
  local tmp; tmp=$(mktemp)
  echo "--- $(date) ---"
  for url in "$@"; do
    curl -sf "$url" | nftset_from_list "$rule" >>"$tmp"
  done
  nftset_from_list "$rule" <"$local_file" >>"$tmp"
  if ! [ -s "$tmp" ]; then
    rm -f "$tmp"
    echo "No domains — skipping."
    return 0
  fi
  mkdir -p /etc/dnsmasq.d && mv "$tmp" "$conf"
  echo "Domains: $(wc -l <"$conf") entries written to $conf"
  /etc/init.d/dnsmasq reload && echo "dnsmasq reloaded." || echo "ERROR: dnsmasq reload failed"
}

# Resolve domain lists to IPs and load them into nft interval sets.
resolve() {
  cat=$1; shift
  echo "==> resolve $cat"
  /usr/sbin/nft-resolve \
    -4 "resolve_${cat}4" -6 "resolve_${cat}6" \
    "$@"
}

# Wrap each call with tee so output goes to both terminal and log file.
dns torrentsites \
  https://raw.githubusercontent.com/sakib-m/Pi-hole-Torrent-Blocklist/refs/heads/main/all-torrent-websites.txt \
  2>&1 | tee /tmp/dns-torrentsites.log
dns pornsites \
  https://nsfw.oisd.nl/ \
  2>&1 | tee /tmp/dns-pornsites.log
dns sites \
  2>&1 | tee /tmp/dns-sites.log
resolve torrenttrackers \
  url=https://raw.githubusercontent.com/ngosang/trackerslist/refs/heads/master/trackers_all.txt \
  domain=https://raw.githubusercontent.com/sakib-m/Pi-hole-Torrent-Blocklist/refs/heads/main/all-torrent-trackers.txt \
  url=/etc/split-routing/local-resolve-torrenttrackers.txt \
  2>&1 | tee /tmp/resolve-torrenttrackers.log
resolve sites \
  domain=/etc/split-routing/local-resolve-sites.txt \
  2>&1 | tee /tmp/resolve-sites.log
EOF
fi

# Remove old per-category scripts replaced by update-routing-sets.
for s in update-resolve-torrenttrackers update-dns-torrentsites \
          update-dns-pornsites update-dns-sites update-resolve-sites; do
  rm -f "/usr/sbin/$s"
done

# ── state tracking ─────────────────────────────────────────────────────────────

STATE_DNSMASQ_SETS=""; STATE_INTERVAL_SETS=""; STATE_FWMARK=""; STATE_ROUTE_TABLE=""; STATE_ROUTE_IPV6=""
[ -f "$STATE" ] && . "$STATE"

# Delete nft sets that were removed or renamed since the last install.
REMOVED=""
for old in $STATE_DNSMASQ_SETS $STATE_INTERVAL_SETS; do
  found=0
  for new in $DNSMASQ_SETS $INTERVAL_SETS; do
    [ "$old" = "$new" ] && found=1 && break
  done
  [ $found -eq 0 ] && REMOVED="$REMOVED $old"
done
if [ -n "$REMOVED" ]; then
  nft flush chain inet fw4 mangle_prerouting 2>/dev/null || true
  for name in $REMOVED; do
    nft delete set inet fw4 ${name}4 2>/dev/null || true
    nft delete set inet fw4 ${name}6 2>/dev/null || true
  done
  echo "Removed stale nft sets:$REMOVED"
fi

# Remove ip rules for old fwmark/table if either changed.
if [ -n "$STATE_FWMARK" ] && { [ "$STATE_FWMARK" != "$FWMARK" ] || [ "$STATE_ROUTE_TABLE" != "$ROUTE_TABLE" ]; }; then
  ip    rule del fwmark "$STATE_FWMARK" lookup "$STATE_ROUTE_TABLE" 2>/dev/null || true
  ip -6 rule del fwmark "$STATE_FWMARK" lookup "$STATE_ROUTE_TABLE" 2>/dev/null || true
fi
# Flush old routing table if it changed.
if [ -n "$STATE_ROUTE_TABLE" ] && [ "$STATE_ROUTE_TABLE" != "$ROUTE_TABLE" ]; then
  ip    route flush table "$STATE_ROUTE_TABLE" 2>/dev/null || true
  ip -6 route flush table "$STATE_ROUTE_TABLE" 2>/dev/null || true
fi
# Remove IPv6 ip rule if ROUTE_IPV6 was disabled.
if [ "$STATE_ROUTE_IPV6" = yes ] && [ "$ROUTE_IPV6" != yes ]; then
  ip -6 rule del fwmark "$STATE_FWMARK" lookup "$STATE_ROUTE_TABLE" 2>/dev/null || true
fi

# ── local lists ────────────────────────────────────────────────────────────────

for f in $LOCAL_FILES; do
  [ -f "$LISTS_DIR/$f" ] || cp "$SCRIPT_DIR/$f" "$LISTS_DIR/$f"
done

# ── cron ───────────────────────────────────────────────────────────────────────

touch "$CRONTAB"
# Remove old per-category cron entries from previous installs.
for _old in update-torrenttrackers update-torrentsites update-pornsites \
            update-resolve- update-dns-; do
  sed -i "/$_old/d" "$CRONTAB" 2>/dev/null || true
done
grep -qF "update-routing-sets" "$CRONTAB" || \
  echo "17 3 * * * /usr/sbin/update-routing-sets >/tmp/routing-sets.log 2>&1" >>"$CRONTAB"
/etc/init.d/cron restart 2>/dev/null || true

# ── dnsmasq capabilities ───────────────────────────────────────────────────────

# dnsmasq runs jailed as user dnsmasq; without CAP_NET_ADMIN it silently
# drops all nftset writes.
mkdir -p /etc/capabilities
cat >/etc/capabilities/dnsmasq.json <<'EOF'
{
	"bounding":    [ "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE" ],
	"effective":   [ "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE" ],
	"ambient":     [ "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE" ],
	"permitted":   [ "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE" ],
	"inheritable": [ "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE" ]
}
EOF

grep -qF "/etc/capabilities/dnsmasq.json" /etc/sysupgrade.conf 2>/dev/null || \
  echo "/etc/capabilities/dnsmasq.json" >>/etc/sysupgrade.conf

/etc/init.d/dnsmasq restart 2>/dev/null || true

# ── nftables.d include (mark chain — survives every fw4 reload) ────────────────

NFTD=/etc/nftables.d/30-split-routing.nft
mkdir -p /etc/nftables.d

# Collect extra-network bridges installed by extra-networks/install.sh.
# Traffic from these bridges is never VPN-marked — they have their own
# forward rules and should always use the normal WAN.
_excl_ifaces=""
for _nc in /etc/extra-networks/*-notify.conf; do
  [ -f "$_nc" ] || continue
  unset IFACE_NAME
  . "$_nc"
  [ -n "${IFACE_NAME:-}" ] && _excl_ifaces="${_excl_ifaces} br-${IFACE_NAME}"
done

{
  printf '# Split-routing sets and mark chain. Managed by install.sh — do not edit.\n'
  for c in $DNS_CATS; do
    printf 'set dns_%s4 { type ipv4_addr; flags dynamic,timeout; timeout %s; }\n' "$c" "$DNS_TIMEOUT"
    printf 'set dns_%s6 { type ipv6_addr; flags dynamic,timeout; timeout %s; }\n' "$c" "$DNS_TIMEOUT"
  done
  for c in $RESOLVE_CATS; do
    printf 'set resolve_%s4 { type ipv4_addr; flags interval; }\n' "$c"
    printf 'set resolve_%s6 { type ipv6_addr; flags interval; }\n' "$c"
  done
  printf 'chain split_routing_mark {\n'
  printf '    type filter hook prerouting priority mangle; policy accept;\n'
  if [ -n "$_excl_ifaces" ]; then
    _excl_list=$(printf '%s' "$_excl_ifaces" | tr ' ' '\n' | grep . | \
      awk '{printf (NR==1?"\"":"\", \"") $0} END{printf "\""}')
    printf '    # Extra-network bridges bypass VPN — they use their own forward rules.\n'
    printf '    iifname { %s } return\n' "$_excl_list"
  fi
  for c in $DNS_CATS; do
    printf '    ip  daddr @dns_%s4 meta mark set %s\n' "$c" "$FWMARK"
    [ "$ROUTE_IPV6" = yes ] && printf '    ip6 daddr @dns_%s6 meta mark set %s\n' "$c" "$FWMARK"
  done
  for c in $RESOLVE_CATS; do
    printf '    ip  daddr @resolve_%s4 meta mark set %s\n' "$c" "$FWMARK"
    [ "$ROUTE_IPV6" = yes ] && printf '    ip6 daddr @resolve_%s6 meta mark set %s\n' "$c" "$FWMARK"
  done
  printf '}\n'
} >"$NFTD"

grep -qF "$NFTD" /etc/sysupgrade.conf 2>/dev/null || echo "$NFTD" >>/etc/sysupgrade.conf

# ── hotplug ────────────────────────────────────────────────────────────────────
# Only manages ip rules and routes — nft sets and mark chain live in nftables.d.

mkdir -p /etc/hotplug.d/iface
cat >"$HOTPLUG" <<'EOF'
#!/bin/sh
[ "$ACTION" = ifup ] || [ "$ACTION" = ifupdate ] || exit 0
. /etc/split-routing/config
ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" || exit 0

while ip    rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null; do :; done
ip    rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE"
ip    route replace default dev "$VPN_IFACE" table "$ROUTE_TABLE"
if [ "$ROUTE_IPV6" = yes ]; then
  while ip -6 rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null; do :; done
  ip -6 rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE"
  ip -6 route replace default dev "$VPN_IFACE" table "$ROUTE_TABLE"
else
  while ip -6 rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null; do :; done
fi
EOF
chmod 0755 "$HOTPLUG"

fw4 -q reload 2>/dev/null || true
ACTION=ifup INTERFACE="$VPN_IFACE" sh "$HOTPLUG" 2>/dev/null || true

# ── state ──────────────────────────────────────────────────────────────────────

cat >"$STATE" <<EOF
STATE_DNSMASQ_SETS="$DNSMASQ_SETS"
STATE_INTERVAL_SETS="$INTERVAL_SETS"
STATE_FWMARK=$FWMARK
STATE_ROUTE_TABLE=$ROUTE_TABLE
STATE_ROUTE_IPV6=$ROUTE_IPV6
EOF

# ── summary ────────────────────────────────────────────────────────────────────

echo "Installed."
echo "  /usr/sbin/nft-resolve"
echo "  /usr/sbin/update-routing-sets"
for f in $LOCAL_FILES; do echo "  $LISTS_DIR/$f"; done
echo "  $CONFIG  (VPN_IFACE=$VPN_IFACE ROUTE_TABLE=$ROUTE_TABLE FWMARK=$FWMARK DNS_TIMEOUT=$DNS_TIMEOUT ROUTE_IPV6=$ROUTE_IPV6)"
echo "  $HOTPLUG"
echo "  Cron: $(grep 'update-routing-sets' $CRONTAB)"
