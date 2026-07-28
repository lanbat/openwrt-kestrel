#!/bin/sh
# Regenerate /etc/nftables.d/25-{iface}-inspect.nft from device state and reload fw4.
# Usage: regen-inspect.sh IFACE_NAME
set -eu

_iface="${1:-}"
[ -n "$_iface" ] || { echo "Usage: regen-inspect.sh IFACE_NAME" >&2; exit 1; }

_base=/etc/kestrel/networks
_labels="${_base}/${_iface}-device-labels"
_ips="${_base}/${_iface}-device-ips"
_ip6s="${_base}/${_iface}-device-ip6s"
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

if [ -f "$_rules" ]; then
    _seen_route_sets=""
    while IFS= read -r _line; do
        # `read` with a tab IFS collapses consecutive delimiters on this
        # shell (busybox ash), which misaligns fields whenever an empty
        # one (port/proto) is followed by a non-empty one (route) — `cut`
        # doesn't have that problem, so extract fields with it instead.
        _mac=$(printf '%s' "$_line" | cut -f1)
        _act=$(printf '%s' "$_line" | cut -f3)
        _port=$(printf '%s' "$_line" | cut -f4)
        _route=$(printf '%s' "$_line" | cut -f6)
        case "$_mac" in '#'*|'') continue ;; esac
        [ "${_act:-}" = allow ] && [ -z "${_port:-}" ] && [ -n "${_route:-}" ] || continue
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        _sk="${_mn}:${_route}"
        case "$_seen_route_sets" in *"|${_sk}|"*) continue ;; esac
        _seen_route_sets="${_seen_route_sets}|${_sk}|"
        printf 'set %s_route_%s_%s_4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; }\n' \
            "$_iface" "$_mn" "$_route"
        printf 'set %s_route_%s_%s_6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; }\n' \
            "$_iface" "$_mn" "$_route"
    done < "$_rules"
fi

printf 'chain %s_inspect {\n' "$_iface"
printf '    type filter hook forward priority 2; policy accept;\n'
printf '    iifname "br-%s" ip daddr %s udp dport 53 accept\n' "$_iface" "$_router_ip"
printf '    iifname "br-%s" ip daddr %s tcp dport 53 accept\n' "$_iface" "$_router_ip"
printf '    iifname "br-%s" udp dport 53 drop\n' "$_iface"
printf '    iifname "br-%s" tcp dport { 53, 853 } drop\n' "$_iface"

if [ -f "$_labels" ] && { [ -f "$_ips" ] || [ -f "$_ip6s" ]; }; then
    while IFS=$(printf '\t') read -r _mac _name; do
        case "$_mac" in '#'*|'') continue ;; esac
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        _ip=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_ips" 2>/dev/null || true)
        _ip6=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_ip6s" 2>/dev/null || true)
        [ -z "$_ip$_ip6" ] && continue
        _lim=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_limits" 2>/dev/null || true)
        _lim="${_lim:-120}"
        if [ -n "$_ip" ]; then
            printf '    iifname "br-%s" ip saddr %s ct state new limit rate over %s/minute drop\n' \
                "$_iface" "$_ip" "$_lim"
            printf '    iifname "br-%s" ip saddr %s ct state new ip daddr @%s_allow_%s_4 accept\n' \
                "$_iface" "$_ip" "$_iface" "$_mn"
        fi
        if [ -n "$_ip6" ]; then
            printf '    iifname "br-%s" ip6 saddr %s ct state new limit rate over %s/minute drop\n' \
                "$_iface" "$_ip6" "$_lim"
            printf '    iifname "br-%s" ip6 saddr %s ct state new ip6 daddr @%s_allow_%s_6 accept\n' \
                "$_iface" "$_ip6" "$_iface" "$_mn"
        fi
    done < "$_labels"
fi

if [ -f "$_labels" ] && { [ -f "$_ips" ] || [ -f "$_ip6s" ]; }; then
    printf '    iifname "br-%s" ct state new limit rate 60/minute log prefix "EXTNET-%s-NEW: " level info drop\n' \
        "$_iface" "$_iface"
fi
printf '}\n'

if [ -f "$_rules" ]; then
    _routing_rules=""
    while IFS= read -r _line; do
        _mac=$(printf '%s' "$_line" | cut -f1)
        _act=$(printf '%s' "$_line" | cut -f3)
        _port=$(printf '%s' "$_line" | cut -f4)
        _route=$(printf '%s' "$_line" | cut -f6)
        case "$_mac" in '#'*|'') continue ;; esac
        [ "${_act:-}" = allow ] && [ -z "${_port:-}" ] && [ -n "${_route:-}" ] || continue
        _vpf="/etc/kestrel/split-routing/vpn-${_route}.conf"
        [ -f "$_vpf" ] || continue
        _vpfm=$(awk -F= '/^FWMARK/{gsub(/[" \t]/, "", $2); print $2; exit}' "$_vpf" 2>/dev/null)
        [ -n "$_vpfm" ] || continue
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        _ip=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_ips" 2>/dev/null || true)
        _ip6=$(awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}' "$_ip6s" 2>/dev/null || true)
        [ -n "$_ip" ] && _routing_rules="${_routing_rules}    iifname \"br-${_iface}\" ip saddr ${_ip} ip daddr @${_iface}_route_${_mn}_${_route}_4 meta mark set ${_vpfm}
"
        [ -n "$_ip6" ] && _routing_rules="${_routing_rules}    iifname \"br-${_iface}\" ip6 saddr ${_ip6} ip6 daddr @${_iface}_route_${_mn}_${_route}_6 meta mark set ${_vpfm}
"
    done < "$_rules"
    if [ -n "$_routing_rules" ]; then
        # Runs at mangle-1 (-151), before split_routing_mark (mangle/-150) which
        # returns early for br-untrusted — this fires first so the mark is
        # already set by the time that chain would otherwise skip it.
        printf 'chain %s_device_routing {\n' "$_iface"
        printf '    type filter hook prerouting priority -151; policy accept;\n'
        printf '%s' "$_routing_rules"
        printf '}\n'
    fi
fi
} > "$_nftd"

grep -qF "$_nftd" /etc/sysupgrade.conf 2>/dev/null || printf '%s\n' "$_nftd" >> /etc/sysupgrade.conf

fw4 -q reload 2>/dev/null || true

# Restore IP-based allow rules from rules file after fw4 reload clears dynamic sets
if [ -f "$_rules" ]; then
    while IFS= read -r _line; do
        _mac=$(printf '%s' "$_line" | cut -f1)
        _dst=$(printf '%s' "$_line" | cut -f2)
        _action=$(printf '%s' "$_line" | cut -f3)
        _port=$(printf '%s' "$_line" | cut -f4)
        case "$_mac" in '#'*|'') continue ;; esac
        [ "${_action:-}" = allow ] || continue
        [ -n "$_port" ] || continue  # domain rules are restored via dnsmasq's nftset=, not here
        _mn=$(printf '%s' "$_mac" | tr -d ':')
        case "$_dst" in
            *.*.*.*) nft add element inet fw4 "${_iface}_allow_${_mn}_4" "{ $_dst }" 2>/dev/null || true ;;
            *:*)     nft add element inet fw4 "${_iface}_allow_${_mn}_6" "{ $_dst }" 2>/dev/null || true ;;
        esac
    done < "$_rules"
fi
