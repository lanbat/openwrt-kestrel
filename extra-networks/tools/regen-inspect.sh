#!/bin/sh
# Regenerate /etc/nftables.d/25-{iface}-inspect.nft from device state and reload fw4.
# Usage: regen-inspect.sh IFACE_NAME
set -eu

_iface="${1:-}"
[ -n "$_iface" ] || { echo "Usage: regen-inspect.sh IFACE_NAME" >&2; exit 1; }

_base=/etc/extra-networks
_labels="${_base}/${_iface}-device-labels"
_ips="${_base}/${_iface}-device-ips"
_limits="${_base}/${_iface}-device-limits"
_rules="${_base}/${_iface}-device-rules"
_nftd="/etc/nftables.d/25-${_iface}-inspect.nft"

_router_ip=$(ip addr show "br-${_iface}" 2>/dev/null | awk '/inet /{split($2,a,"/");print a[1];exit}')
if [ -z "$_router_ip" ]; then
    unset SUBNET
    [ -f "${_base}/${_iface}-notify.conf" ] && . "${_base}/${_iface}-notify.conf" 2>/dev/null || true
    _router_ip="${SUBNET:-192.168.1}.1"
fi

mkdir -p /etc/nftables.d

{
printf '# Device inspect chain for %s — managed by regen-inspect.sh\n' "$_iface"

if [ -f "$_labels" ]; then
    while IFS=$(printf '\t') read -r _mac _name; do
        case "$_mac" in '#'*|'') continue ;; esac
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        printf 'set %s_allow_%s_4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; }\n' \
            "$_iface" "$_mn"
        printf 'set %s_allow_%s_6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; }\n' \
            "$_iface" "$_mn"
    done < "$_labels"
fi

printf 'chain %s_inspect {\n' "$_iface"
printf '    type filter hook forward priority 2; policy accept;\n'
printf '    iifname "br-%s" ip daddr %s udp dport 53 accept\n' "$_iface" "$_router_ip"
printf '    iifname "br-%s" ip daddr %s tcp dport 53 accept\n' "$_iface" "$_router_ip"
printf '    iifname "br-%s" udp dport 53 drop\n' "$_iface"
printf '    iifname "br-%s" tcp dport { 53, 853 } drop\n' "$_iface"

if [ -f "$_labels" ] && [ -f "$_ips" ]; then
    while IFS=$(printf '\t') read -r _mac _name; do
        case "$_mac" in '#'*|'') continue ;; esac
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        _ip=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_ips" 2>/dev/null || true)
        [ -z "$_ip" ] && continue
        _lim=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_limits" 2>/dev/null || true)
        _lim="${_lim:-120}"
        printf '    iifname "br-%s" ip saddr %s ct state new limit rate over %s/minute drop\n' \
            "$_iface" "$_ip" "$_lim"
        printf '    iifname "br-%s" ip saddr %s ct state new ip daddr @%s_allow_%s_4 accept\n' \
            "$_iface" "$_ip" "$_iface" "$_mn"
    done < "$_labels"
fi

printf '    iifname "br-%s" ct state new log prefix "EXTNET-%s-NEW: " level info drop\n' \
    "$_iface" "$_iface"
printf '}\n'
} > "$_nftd"

grep -qF "$_nftd" /etc/sysupgrade.conf 2>/dev/null || printf '%s\n' "$_nftd" >> /etc/sysupgrade.conf

fw4 -q reload 2>/dev/null || true

# Restore IP-based allow rules from rules file after fw4 reload clears dynamic sets
if [ -f "$_rules" ]; then
    while IFS=$(printf '\t') read -r _mac _dst _action _port _proto; do
        case "$_mac" in '#'*|'') continue ;; esac
        case "$_dst" in *.*.*.*) ;; *) continue ;; esac
        [ "${_action:-}" = allow ] || continue
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        nft add element inet fw4 "${_iface}_allow_${_mn}_4" "{ $_dst }" 2>/dev/null || true
    done < "$_rules"
fi
