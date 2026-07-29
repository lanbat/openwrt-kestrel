#!/bin/sh
# Show status of all isolated networks managed by install.sh.

_hr() { printf '%.0s─' $(seq 1 60); echo; }

_zone_info() {
    zone="$1"
    iface=$(uci -q get firewall."${zone}_zone".network 2>/dev/null || echo "$zone")
    bridge="br-$iface"

    printf '\n'
    _hr
    printf '  %s\n' "$zone"
    _hr

    # Bridge state
    if ip link show "$bridge" >/dev/null 2>&1; then
        ip=$(ip addr show "$bridge" 2>/dev/null \
             | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
        state=$(ip link show "$bridge" | awk '/state/ { print $9 }')
        printf '  Bridge:   %s  %s  (%s)\n' "$bridge" "$ip" "$state"
    else
        printf '  Bridge:   %s  (not up)\n' "$bridge"
        return
    fi

    # WiFi — find wireless sections pointing at this network
    for wuci in $(uci show wireless 2>/dev/null \
                  | awk -F= "/\\.network='?${iface}'?/ { gsub(/wireless\\./,\"\",\$1); gsub(/\\.network/,\"\",\$1); print \$1 }"); do
        ssid_val=$(uci -q get wireless."$wuci".ssid 2>/dev/null || echo '?')
        enc=$(uci -q get wireless."$wuci".encryption 2>/dev/null || echo '?')
        radio=$(uci -q get wireless."$wuci".device 2>/dev/null || echo '?')
        printf '  WiFi:     %-30s (%s, %s on %s)\n' "$ssid_val" "$wuci" "$enc" "$radio"
    done

    # Connected clients
    clients=0
    for wif in $(iw dev 2>/dev/null | awk '/Interface/ { print $2 }'); do
        master=$(ip link show "$wif" 2>/dev/null | awk '/master/ { print $NF; exit }')
        [ "$master" = "$bridge" ] || continue
        while IFS= read -r line; do
            case "$line" in
                Station*) mac=$(echo "$line" | awk '{print $2}')
                          clients=$(( clients + 1 ))
                          printf '  Client:   %s (via %s)\n' "$mac" "$wif" ;;
            esac
        done < <(iw dev "$wif" station dump 2>/dev/null)
    done
    [ "$clients" -eq 0 ] && printf '  Clients:  none\n'

    # DHCP leases
    subnet_prefix=$(ip addr show "$bridge" 2>/dev/null \
                    | awk '/inet / { split($2,a,"."); print a[1]"."a[2]"."a[3] }')
    if [ -n "$subnet_prefix" ]; then
        leases=$(grep "^[0-9]" /tmp/dhcp.leases 2>/dev/null \
                 | awk -v p="$subnet_prefix" '$3 ~ p { print $3, $4, $2 }')
        if [ -n "$leases" ]; then
            echo "$leases" | while read -r lip lname lmac; do
                printf '  Lease:    %-16s %-20s %s\n' "$lip" "$lname" "$lmac"
            done
        else
            printf '  Leases:   none\n'
        fi
    fi

    # Rate limit — nft displays meter rules as "add @name { ... }" at list time
    _rlt=$(nft list chain inet fw4 "${iface}_ratelimit" 2>/dev/null)
    rl=$(echo "$_rlt" | awk '!/add @/ && /iifname.*limit rate over/ {
             for(i=1;i<=NF;i++) if($i=="over") { print $(i+1), $(i+2); exit } }')
    [ -n "$rl" ] && printf '  Rate:     over %s (aggregate)\n' "$rl"

    prl=$(echo "$_rlt" | awk '/add @.*limit rate over/ {
              for(i=1;i<=NF;i++) if($i=="over") { print $(i+1), $(i+2); exit } }' | head -1)
    [ -n "$prl" ] && printf '  Rate:     over %s (per device)\n' "$prl"

    # Traffic counters (since last fw4 reload)
    _ctr=$(nft list chain inet fw4 "${iface}_counter" 2>/dev/null)
    if [ -n "$_ctr" ]; then
        _up=$(echo "$_ctr" | awk "/iifname.*br-${iface}.*counter/ {
            for(i=1;i<=NF;i++) if(\$i==\"bytes\") { b=\$(i+1); exit }
            if(b>=1073741824) printf \"%.1f GB\", b/1073741824
            else printf \"%.1f MB\", b/1048576
        }")
        _dn=$(echo "$_ctr" | awk "/oifname.*br-${iface}.*counter/ {
            for(i=1;i<=NF;i++) if(\$i==\"bytes\") { b=\$(i+1); exit }
            if(b>=1073741824) printf \"%.1f GB\", b/1073741824
            else printf \"%.1f MB\", b/1048576
        }")
        printf '  Traffic:  ↑ %s  ↓ %s  (since fw4 reload)\n' "${_up:-0 B}" "${_dn:-0 B}"
    fi

    # Access schedule
    if [ -f /etc/nftables.d/30-${iface}-timeblock.nft ]; then
        printf '  Schedule: BLOCKED (internet off)\n'
    else
        sched=$(crontab -l 2>/dev/null | grep "# access-${iface}" | head -1 \
                | awk '{print $2}')
        [ -n "$sched" ] && printf '  Schedule: internet hours restricted (see access-schedule.sh)\n'
    fi

    # Active port forwards
    fwds=$(uci show firewall 2>/dev/null \
           | awk -F= '/=redirect/ { sec=$1; sub(/=redirect/,"",sec); print sec }')
    for s in $fwds; do
        src=$(uci -q get firewall."$s".src 2>/dev/null)
        [ "$src" = "$zone" ] || continue
        name=$(uci -q get firewall."$s".name 2>/dev/null)
        port=$(uci -q get firewall."$s".src_dport 2>/dev/null)
        dest=$(uci -q get firewall."$s".dest_ip 2>/dev/null)
        printf '  Forward:  :%s → %s  (%s)\n' "$port" "$dest" "$name"
    done

    # LAN access
    lan_fwd=$(uci -q get firewall."lan_${iface}".src 2>/dev/null)
    if [ "$lan_fwd" = lan ]; then
        printf '  LAN:      can reach %s devices\n' "$zone"
    fi
}

# Find all non-lan/wan firewall zones (sections of type=zone only).
zones=$(for s in $(uci show firewall 2>/dev/null \
        | awk -F= '/=zone$/ { gsub(/firewall\./,"",$1); print $1 }'); do
    name=$(uci -q get firewall."$s".name 2>/dev/null || true)
    [ "$name" = lan ] || [ "$name" = wan ] && continue
    [ -n "$name" ] && echo "$name"
done)

if [ -z "$zones" ]; then
    echo "No isolated networks found."
    exit 0
fi

printf '\n  kestrel — network status\n'
for z in $zones; do
    _zone_info "$z"
done
printf '\n'
