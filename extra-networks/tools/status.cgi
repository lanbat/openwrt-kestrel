#!/bin/sh
# CGI: live status dashboard for all isolated networks.
# Installed to /www/cgi-bin/status by install.sh when NOTIFY_URL is set.
# Only reachable from LAN — isolated zones have INPUT=REJECT.

BASE_DIR=/etc/extra-networks
[ -f "${BASE_DIR}/_lib.sh" ] && . "${BASE_DIR}/_lib.sh"

printf 'Content-Type: text/html\r\n\r\n'

hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo router)
now=$(date '+%H:%M:%S on %d/%m/%Y')
now_ts=$(date +%s)

_nft_bytes() {
    if [ "$2" = in ]; then
        nft list chain inet fw4 "$1" 2>/dev/null \
            | awk '/iifname.*counter/ { for(i=1;i<=NF;i++) if($i=="bytes") { print $(i+1); exit } }'
    else
        nft list chain inet fw4 "$1" 2>/dev/null \
            | awk '/oifname.*counter/ { for(i=1;i<=NF;i++) if($i=="bytes") { print $(i+1); exit } }'
    fi
}

_human() {
    awk -v b="${1:-0}" 'BEGIN {
        if      (b+0 >= 1073741824) printf "%.1f GB", b/1073741824
        else if (b+0 >= 1048576)   printf "%.1f MB", b/1048576
        else if (b+0 >= 1024)      printf "%.1f KB", b/1024
        else                       printf "%d B",     b+0
    }'
}

_html() { printf '%s' "$1" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;s/"/\&quot;/g'; }

_exp_str() {
    _rem=$(( $1 - now_ts ))
    if   [ "$_rem" -le 0 ];     then printf 'expired'
    elif [ "$_rem" -gt 86400 ]; then printf '%dd' "$(( _rem / 86400 ))"
    elif [ "$_rem" -gt 3600 ];  then printf '%dh %dm' "$(( _rem / 3600 ))" "$(( (_rem % 3600) / 60 ))"
    else                             printf '%dm' "$(( _rem / 60 ))"
    fi
}

# Cache logread and crontab once — both used in multiple per-network sections
_logdata=$(logread 2>/dev/null | tail -n 500)
_crontab=$(crontab -l 2>/dev/null)

cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Status — ${hostname}</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:1rem;color:#111;background:#fff}
h1{font-size:1.4rem;margin-bottom:.15rem}
.sub{color:#888;font-size:.85rem;margin-bottom:2rem}
h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:#888;
   border-bottom:1px solid #e0e0e0;padding-bottom:.3rem;margin:1.75rem 0 .6rem}
.card{background:#f5f5f5;border-radius:8px;padding:.7rem 1rem;margin:.4rem 0}
.row{display:flex;justify-content:space-between;font-size:.9rem;padding:.18rem 0}
.lbl{color:#666}.val{font-weight:600}
.ok{color:#2e7d32}.warn{color:#c62828}.dim{color:#aaa}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:.875rem;margin:.4rem 0;
      border:1px solid #ececec;border-radius:10px;overflow:hidden}
th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;
   color:#777;background:#fafafa;padding:.45rem .6rem;border-bottom:1px solid #e0e0e0}
td{padding:.5rem .6rem;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:last-child td{border-bottom:0}
tr:hover td{background:#fcfcfc}
a{color:#1976d2;text-decoration:none}
form{display:inline}
button{font-size:.75rem;padding:.15rem .45rem;cursor:pointer;background:#1976d2;
       color:#fff;border:none;border-radius:4px}
.actions{display:inline-flex;gap:.25rem;align-items:center;margin-left:.45rem;vertical-align:middle}
.actions form{display:inline-flex}
.actions button{font-weight:600;padding:.22rem .55rem;border-radius:999px;box-shadow:0 1px 2px rgba(0,0,0,.12)}
.btn-ok{background:#2e7d32}
.btn-deny{background:#c62828}
.btn-danger{background:#c62828}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:.16rem .52rem;
       font-size:.72rem;font-weight:700;letter-spacing:.02em}
.badge-approved{color:#1b5e20;background:#e8f5e9}
.badge-pending{color:#8a5a00;background:#fff3cd}
.badge-denied{color:#b71c1c;background:#ffebee}
.badge-untracked{color:#666;background:#eeeeee}
.badge-revoked{color:#0d47a1;background:#e3f2fd}
.badge-connected{color:#1b5e20;background:#e8f5e9}.badge-disconnected{color:#555;background:#eee}
.net-desc{color:#555;font-size:.88rem;margin:-.4rem 0 .6rem}
.qr{display:flex;align-items:stretch;gap:1rem}
.qr-info{font-size:.9rem;display:flex;flex-direction:column;flex:1;min-width:0}
.qr-info strong{margin-bottom:.2rem}
.q-lbl{font-size:.72rem;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-top:.4rem}
.q-lbl:first-child{margin-top:0}
.qr-info code{background:#e8e8e8;padding:.2rem .45rem;border-radius:4px;
              word-break:break-all;font-size:.85rem;align-self:flex-start}
.qr-info form{margin-top:auto;padding-top:.6rem;text-align:right}
</style></head><body>
<h1>${hostname}</h1>
<div class="sub">${now} &nbsp;·&nbsp; <a href="">Refresh</a></div>
HTML

# ── System ─────────────────────────────────────────────────────────────────────

_uptime=$(awk '{s=$1; d=int(s/86400); h=int((s%86400)/3600); m=int((s%3600)/60);
    if(d>0) printf "%dd %dh %dm",d,h,m; else printf "%dh %dm",h,m}' /proc/uptime)
_mem=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{
    printf "%d MB free / %d MB total", a/1024, t/1024}' /proc/meminfo)
_load=$(awk '{print $1" "$2" "$3}' /proc/loadavg)
_wan_dev=$(ip route show default 2>/dev/null \
    | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
_wan_ip=$(ip addr show "$_wan_dev" 2>/dev/null \
    | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
_wan_ipv6=$(ip -6 addr show dev "$_wan_dev" scope global 2>/dev/null \
    | awk '/inet6/{split($2,a,"/"); print a[1]; exit}')

printf '<h2>System</h2><div class="card">'
printf '<div class="row"><span class="lbl">Uptime</span><span class="val">%s</span></div>' "$_uptime"
printf '<div class="row"><span class="lbl">Memory</span><span class="val">%s</span></div>' "$_mem"
printf '<div class="row"><span class="lbl">Load</span><span class="val">%s</span></div>' "$_load"
if [ -n "$_wan_ip" ] && [ -n "$_wan_ipv6" ]; then
    printf '<div class="row"><span class="lbl">WAN IPv4</span><span class="val">%s</span></div>' "$_wan_ip"
    printf '<div class="row"><span class="lbl">WAN IPv6</span><span class="val">%s</span></div>' "$_wan_ipv6"
elif [ -n "$_wan_ip" ]; then
    printf '<div class="row"><span class="lbl">WAN IP</span><span class="val">%s</span></div>' "$_wan_ip"
fi
printf '</div>\n'

# ── VPN ────────────────────────────────────────────────────────────────────────

VPN_CFG=/etc/split-routing/config
_vpn_iface=""
if [ -f "$VPN_CFG" ]; then
    unset VPN_IFACE ROUTE_TABLE FWMARK NOTIFY_URL
    . "$VPN_CFG"
    _vpn_iface="${VPN_IFACE:-}"
    _if_up=no; ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" && _if_up=yes
    _rule=no;  ip rule show 2>/dev/null | grep -q "lookup ${ROUTE_TABLE}" && _rule=yes
    _rt=no;    ip route show table "$ROUTE_TABLE" 2>/dev/null | grep -q "^default" && _rt=yes
    if   [ "$_if_up$_rule$_rt" = yesyesyes ]; then _vc=ok;   _vl="Up"
    elif [ "$_if_up" = yes ];                  then _vc=warn; _vl="Up — routing fault"
    else                                            _vc=warn; _vl="Down"
    fi
    printf '<h2>VPN</h2><div class="card">'
    printf '<div class="row"><span class="lbl">Interface</span><span class="val">%s</span></div>' "$VPN_IFACE"
    printf '<div class="row"><span class="lbl">Status</span><span class="val %s">%s</span></div>' "$_vc" "$_vl"
    printf '</div>\n'
fi

# ── WireGuard server peers ─────────────────────────────────────────────────────
# Show any WireGuard interface that acts as a server (no outbound endpoint on peers).

if command -v wg >/dev/null 2>&1; then
    for _wgs in $(uci show network 2>/dev/null \
        | awk -F= "/\\.proto='wireguard'/"'{sub(/\.proto.*/,"",$1);sub(/^network\./,"",$1);print $1}'); do

        [ "$_wgs" = "$_vpn_iface" ] && continue

        # Detect server: none of its UCI peers have endpoint_host set
        _wgs_is_server=yes; _pi=0
        while true; do
            _pk=$(uci -q get "network.@wireguard_${_wgs}[${_pi}].public_key" 2>/dev/null || true)
            [ -z "$_pk" ] && break
            _ep=$(uci -q get "network.@wireguard_${_wgs}[${_pi}].endpoint_host" 2>/dev/null || true)
            [ -n "$_ep" ] && { _wgs_is_server=no; break; }
            _pi=$(( _pi + 1 ))
        done
        [ "$_wgs_is_server" = no ] && continue

        _wgs_dump=$(wg show "$_wgs" dump 2>/dev/null | tail -n +2)
        _wgs_tmp="/tmp/status_cgi_wg_${_wgs}"
        rm -f "$_wgs_tmp"

        _pi=0
        while true; do
            _pk=$(uci -q get "network.@wireguard_${_wgs}[${_pi}].public_key" 2>/dev/null || true)
            [ -z "$_pk" ] && break
            _desc=$(uci -q get "network.@wireguard_${_wgs}[${_pi}].description" 2>/dev/null || true)
            _aips=$(uci -q get "network.@wireguard_${_wgs}[${_pi}].allowed_ips" 2>/dev/null \
                | awk '{printf "%s%s", sep, $0; sep=", "} END{if(!NR)print "—"}')
            _pi=$(( _pi + 1 ))

            _peer_label="${_desc:-$(printf '%s' "$_pk" | head -c 8)…}"
            _wgs_peer=$(printf '%s\n' "$_wgs_dump" | awk -F'\t' -v pk="$_pk" '$1==pk{print;exit}')
            _dep=$(printf '%s\n' "$_wgs_peer" | cut -f3)
            _dhs=$(printf '%s\n' "$_wgs_peer" | cut -f5)
            _drx=$(printf '%s\n' "$_wgs_peer" | cut -f6)
            _dtx=$(printf '%s\n' "$_wgs_peer" | cut -f7)

            _online=no
            _hs_str="—"
            if [ "${_dhs:-0}" -gt 0 ] 2>/dev/null; then
                _ago=$(( now_ts - _dhs ))
                [ "$_ago" -lt 180 ] && _online=yes
                if   [ "$_ago" -lt 60 ];    then _hs_str="${_ago}s ago"
                elif [ "$_ago" -lt 3600 ];  then _hs_str="$(( _ago / 60 ))m ago"
                elif [ "$_ago" -lt 86400 ]; then _hs_str="$(( _ago / 3600 ))h ago"
                else                             _hs_str="$(( _ago / 86400 ))d ago"
                fi
            fi

            _ep_disp="—"; [ -n "$_dep" ] && [ "$_dep" != "(none)" ] && _ep_disp="$(_html "$_dep")"
            _tr_disp="—"
            [ "${_drx:-0}" -gt 0 ] || [ "${_dtx:-0}" -gt 0 ] 2>/dev/null && \
                _tr_disp="$(_human "${_drx:-0}") / $(_human "${_dtx:-0}")"
            printf '<tr><td>%s</td><td>%s</td><td class="dim">%s</td><td class="%s">%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$(_html "$_peer_label")" \
                "$_ep_disp" \
                "$(_html "$(printf '%s' "$_aips" | tr ' ' ',')")" \
                "$([ "$_online" = yes ] && echo ok || echo dim)" \
                "$([ "$_online" = yes ] && echo '●' || echo '○')" \
                "$_hs_str" \
                "$_tr_disp"
        done >> "$_wgs_tmp" 2>/dev/null

        if [ -s "$_wgs_tmp" ]; then
            printf '<h2>WireGuard — %s</h2>\n' "$(_html "$_wgs")"
            printf '<table><tr><th>Peer</th><th>Endpoint</th><th>Allowed IPs</th><th>Online</th><th>Last seen</th><th>Traffic ↓/↑</th></tr>\n'
            cat "$_wgs_tmp"
            printf '</table>\n'
        fi
        rm -f "$_wgs_tmp"
    done
fi

# ── Networks ───────────────────────────────────────────────────────────────────

_domain=$(uci -q get dhcp.@dnsmasq[0].domain 2>/dev/null || true)
_domain="${_domain:-lan}"

for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB \
          RATE_LIMIT RATE_LIMIT_PER_DEVICE DNS_SERVER DNS_SERVER_V6 ISOLATE LAN_ACCESS DOT \
          SHOW_QR NOTIFY_JOIN JOIN_APPROVAL JOIN_HISTORY_RETENTION ROTATE_PASSWORD DESCRIPTION
    . "$_conf"
    _iface="${IFACE_NAME:-}"
    [ -z "$_iface" ] && continue
    [ "$_iface" = untrusted ] && SHOW_QR=no

    _ssid=$(uci -q get wireless."$_iface".ssid 2>/dev/null || true)
    _up=no; ip link show "br-${_iface}" 2>/dev/null | grep -q "LOWER_UP" && _up=yes
    _rx=$(_nft_bytes "${_iface}_counter" in);  _rxh=$(_human "$_rx")
    _tx=$(_nft_bytes "${_iface}_counter" out); _txh=$(_human "$_tx")
    # WiFi interface for signal strength (e.g. phy0-ap1 for br-guest)
    _wlan=$(ip link show master "br-${_iface}" 2>/dev/null \
        | awk 'NR==1{n=$2; sub(/@.*/,"",n); print n}')
    _assoc=$([ -n "$_wlan" ] && iwinfo "$_wlan" assoclist 2>/dev/null || true)

    # IPv6 neighbour table for this bridge: MAC → global/ULA address (skip link-local)
    _neigh6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
        | awk '!/^fe80:/ && /lladdr/{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1)"\t"$1; break}}')

    _devs=$(
        awk -v s="${SUBNET}." '$3~s{print $4"\t"$3"\t"$2"\t"$1}' /tmp/dhcp.leases 2>/dev/null
        printf '%s\n' "$_neigh6" | while IFS=$(printf '\t') read -r _nmac _nip6; do
            [ -n "$_nmac" ] || continue
            awk -v m="$_nmac" 'tolower($2)==tolower(m){found=1} END{exit found?0:1}' /tmp/dhcp.leases 2>/dev/null \
                || printf '*\t-\t%s\t0\n' "$_nmac"
        done
    )
    _dc=$(printf '%s\n' "$_devs" | awk 'NF{c++}END{print c+0}')

    # ── Network header + config card ──────────────────────────────────────────

    printf '<h2>%s%s</h2>' "$(_html "$_iface")" \
        "${_ssid:+ — $(_html "$_ssid")}"
    [ -n "${DESCRIPTION:-}" ] && printf '<div class="net-desc">%s</div>\n' "$(_html "$DESCRIPTION")"
    printf '<div class="card">'
    printf '<div class="row"><span class="lbl">State</span><span class="val %s">%s</span></div>' \
        "$([ "$_up" = yes ] && echo ok || echo warn)" \
        "$([ "$_up" = yes ] && echo Up || echo Down)"
    [ -n "${SUBNET:-}" ] && \
        printf '<div class="row"><span class="lbl">Subnet</span><span class="val">%s.0/24</span></div>' "$SUBNET"
    _ipv6_prefixes=$(ip -6 addr show "br-${_iface}" scope global 2>/dev/null \
        | awk '/inet6/{print $2}')
    for _ipv6_prefix in $_ipv6_prefixes; do
        case "$_ipv6_prefix" in
            fd*|fc*) _ipv6_lbl="IPv6 prefix (ULA)" ;;
            *)       _ipv6_lbl="IPv6 prefix" ;;
        esac
        printf '<div class="row"><span class="lbl">%s</span><span class="val">%s</span></div>' \
            "$_ipv6_lbl" "$(_html "$_ipv6_prefix")"
    done
    printf '<div class="row"><span class="lbl">Traffic ↓ / ↑</span><span class="val">%s / %s</span></div>' \
        "$_rxh" "$_txh"
    printf '<div class="row"><span class="lbl">Devices</span><span class="val">%s</span></div>' "$_dc"
    if [ -n "${DNS_SERVER:-}" ]; then
        _dns_v6_str=""
        [ -n "${DNS_SERVER_V6:-}" ] && _dns_v6_str=" / $(_html "$DNS_SERVER_V6")"
        printf '<div class="row"><span class="lbl">DNS</span><span class="val">%s%s%s</span></div>' \
            "$(_html "$DNS_SERVER")" "$_dns_v6_str" \
            "$([ "${DOT:-no}" = yes ] && echo ' (DoT)' || true)"
    fi
    if [ -n "${RATE_LIMIT:-}" ] && [ "${RATE_LIMIT:-0}" != "0" ]; then
        _prd=""
        [ "${RATE_LIMIT_PER_DEVICE:-0}" != "0" ] && _prd=" / $(_html "$RATE_LIMIT_PER_DEVICE") per device"
        printf '<div class="row"><span class="lbl">Rate limit</span><span class="val">%s%s</span></div>' \
            "$(_html "$RATE_LIMIT")" "$_prd"
    fi
    printf '<div class="row"><span class="lbl">LAN access</span><span class="val">%s</span></div>' \
        "$([ "${LAN_ACCESS:-no}" = yes ] && echo yes || echo no)"
    printf '<div class="row"><span class="lbl">Isolation</span><span class="val">%s</span></div>' \
        "$([ "${ISOLATE:-no}" = yes ] && echo on || echo off)"
    printf '<div class="row"><span class="lbl">Join alerts</span><span class="val">%s</span></div>' \
        "$([ "${NOTIFY_JOIN:-no}" = yes ] && echo on || echo off)"
    [ "${BANDWIDTH_THRESHOLD_MB:-0}" != 0 ] && \
        printf '<div class="row"><span class="lbl">Bandwidth alert</span><span class="val">%s MB/h</span></div>' \
            "$BANDWIDTH_THRESHOLD_MB"
    printf '</div>\n'

    # ── WiFi QR code + rotate button ─────────────────────────────────────────

    _key=$(uci -q get wireless."$_iface".key 2>/dev/null || true)
    if [ "${SHOW_QR:-no}" = yes ] && [ -n "$_key" ] && [ -n "$_ssid" ] && command -v qrencode >/dev/null 2>&1; then
        _enc=$(uci -q get wireless."$_iface".encryption 2>/dev/null || true)
        case "$_enc" in sae*|psk*) _wtype=WPA ;; wep*) _wtype=WEP ;; *) _wtype=nopass ;; esac
        _qrdata=$(qrencode -t ASCII -m 2 -o - \
            "WIFI:S:${_ssid};T:${_wtype};P:${_key};;" 2>/dev/null | tr '\n' '|')
        printf '<div class="card qr"><div class="qr-canvas" data-qr="%s"></div><div class="qr-info"><span class="q-lbl">SSID</span><strong>%s</strong><span class="q-lbl">Password</span><code>%s</code>' \
            "$_qrdata" "$(_html "$_ssid")" "$(_html "$_key")"
        [ "${ROTATE_PASSWORD:-no}" = yes ] && \
            printf '<form method="POST" action="/cgi-bin/rotate-password"><input type="hidden" name="net" value="%s"><button class="btn-danger" type="submit" onclick="return confirm('\''Rotate the WiFi password for %s? All connected devices will need to reconnect with the new password.'\'')">Rotate password</button></form>' \
                "$(_html "$_iface")" "$(_html "$_iface")"
        printf '</div></div>\n'
    fi

    # ── Device table ──────────────────────────────────────────────────────────

    if [ -n "$_devs" ]; then
        _bw_data=$(nft list set inet fw4 "${_iface}_device_bytes"  2>/dev/null)
        _bw_data6=$(nft list set inet fw4 "${_iface}_device_bytes6" 2>/dev/null)
        _join_pending="${BASE_DIR}/${_iface}-join-pending"
        _join_approved="${BASE_DIR}/${_iface}-join-approved"
        _join_denied="${BASE_DIR}/${_iface}-join-denied"
        _hdr_bw=$([ -n "$_bw_data$_bw_data6" ] && echo yes || echo no)
        _hdr_sig=$([ -n "$_assoc" ] && echo yes || echo no)
        _hdr_ip6=no
        [ -n "$_ipv6_prefixes" ] && _hdr_ip6=yes
        uci -q get dhcp."$_iface".dhcpv6 2>/dev/null | grep -q server && _hdr_ip6=yes || true

        printf '<table><tr><th>Hostname</th><th>Label</th><th>DNS</th><th>IPv4</th><th>Joined</th>'
        [ "$_hdr_ip6" = yes ] && printf '<th>IPv6</th>'
        [ "${JOIN_APPROVAL:-no}" = yes ] && printf '<th>Join access</th>'
        printf '<th>MAC</th>'
        [ "$_hdr_sig" = yes ] && printf '<th>Signal</th>'
        [ "$_hdr_bw"  = yes ] && printf '<th>Traffic</th>'
        printf '<th>Lease expires</th></tr>\n'

        printf '%s\n' "$_devs" | while IFS=$(printf '\t') read -r _hn _ip _mac _exp_ts; do
            _sig=""
            [ "$_hdr_sig" = yes ] && \
                _sig=$(printf '%s\n' "$_assoc" \
                    | awk -v m="$_mac" 'tolower($1)==tolower(m){ print $2" dBm"; exit }')

            # Always resolve IPv6 — used for both the column and bw6 lookup
            _ipv6=$(printf '%s\n' "$_neigh6" \
                | awk -v m="$_mac" 'tolower($1)==tolower(m){print $2; exit}')

            _bw=""
            if [ "$_hdr_bw" = yes ]; then
                _b4=$(printf '%s\n' "$_bw_data" \
                    | awk -v ip="$_ip" '$0~ip && /bytes/ { for(i=1;i<=NF;i++) if($i=="bytes") {print $(i+1); exit} }')
                _b6=0
                [ -n "$_bw_data6" ] && [ -n "$_ipv6" ] && \
                    _b6=$(printf '%s\n' "$_bw_data6" \
                        | awk -v ip="$_ipv6" '$0~ip && /bytes/ { for(i=1;i<=NF;i++) if($i=="bytes") {print $(i+1); exit} }')
                _total=$(( ${_b4:-0} + ${_b6:-0} ))
                [ "$_total" -gt 0 ] && _bw=$(_human "$_total")
            fi

            _hn_disp="—"; [ "$_hn" != "*" ] && [ -n "$_hn" ] && _hn_disp="$(_html "$_hn")"
            _lookup_ip="$_ip"; [ "$_lookup_ip" = "-" ] && _lookup_ip="$_ipv6"
            _dns=$(nslookup "$_lookup_ip" 2>/dev/null \
                | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}')
            [ -z "$_dns" ] && _dns="—"
            _joined=$(awk -F'\t' -v m="$_mac" \
                'tolower($1)==tolower(m){print $2; exit}' \
                /tmp/extra-networks-joins 2>/dev/null || true)
            [ -z "$_joined" ] && _joined="—"
            _dlabel=$(awk -v m="$_mac" \
                'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
                "${BASE_DIR}/${_iface}-device-labels" 2>/dev/null || true)
            if [ -n "$_dlabel" ]; then
                _label_cell="$(_html "$_dlabel")"
            elif [ "${JOIN_APPROVAL:-no}" = yes ]; then
                _label_cell=$(printf '<form method="POST" action="/cgi-bin/approve-join" style="margin:0"><input type="hidden" name="net" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="action" value="set_label"><input type="text" name="label" placeholder="Add label" maxlength="40" style="padding:.2rem .35rem;border:1px solid #ccc;border-radius:3px;font-size:.8rem"><button type="submit" style="padding:.2rem .4rem;margin-left:.2rem;font-size:.8rem;border:1px solid #aaa;border-radius:3px;background:#f5f5f5;cursor:pointer">Save</button></form>' \
                    "$(_html "$_iface")" "$(_html "$_mac")")
            else
                _label_cell="—"
            fi
            printf '<tr><td>%s</td><td>%s</td><td class="dim">%s</td><td>%s</td><td class="dim">%s</td>' \
                "$_hn_disp" "$_label_cell" "$(_html "$_dns")" \
                "$([ "$_ip" = "-" ] && echo "—" || _html "$_ip")" "$_joined"
            [ "$_hdr_ip6" = yes ] && printf '<td class="dim">%s</td>' "${_ipv6:----}"
            if [ "${JOIN_APPROVAL:-no}" = yes ]; then
                _join_state="Untracked"
                grep -qixF "$_mac" "$_join_approved" 2>/dev/null && _join_state="Approved"
                grep -qixF "$_mac" "$_join_denied" 2>/dev/null && _join_state="Denied"
                grep -qi "^${_mac} " "$_join_pending" 2>/dev/null && [ "$_join_state" = Untracked ] && _join_state="Pending"
                _join_class=$(printf '%s' "$_join_state" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
                printf '<td><span class="badge badge-%s">%s</span><span class="actions">' "$_join_class" "$_join_state"
                if [ "$_join_state" != Approved ]; then
                    _jhost=$([ "$_hn" != "*" ] && printf '%s' "$_hn" || true)
                    _approve_ip="$_ip"; [ "$_approve_ip" = "-" ] && _approve_ip="$_ipv6"
                    printf '<form method="POST" action="/cgi-bin/approve-join">'
                    printf '<input type="hidden" name="net" value="%s"><input type="hidden" name="ip" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="approve">' \
                        "$(_html "$_iface")" "$(_html "$_approve_ip")" "$(_html "$_mac")" "$(_html "$_jhost")"
                    printf '<input type="text" name="label" value="%s" placeholder="Label (required)" required maxlength="40" style="display:block;padding:.25rem .4rem;margin:.25rem 0;border:1px solid #ccc;border-radius:4px;font-size:.8rem">' \
                        "$(_html "$_dlabel")"
                    printf '<button class="btn-ok" type="submit">Approve</button></form>'
                fi
                if [ "$_join_state" != Approved ] && [ "$_join_state" != Denied ]; then
                    _jhost=$([ "$_hn" != "*" ] && printf '%s' "$_hn" || true)
                    _approve_ip="$_ip"; [ "$_approve_ip" = "-" ] && _approve_ip="$_ipv6"
                    printf '<form method="POST" action="/cgi-bin/approve-join">'
                    printf '<input type="hidden" name="net" value="%s"><input type="hidden" name="ip" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="deny">' \
                        "$(_html "$_iface")" "$(_html "$_approve_ip")" "$(_html "$_mac")" "$(_html "$_jhost")"
                    printf '<button class="btn-deny" type="submit">Deny</button></form>'
                fi
                printf '</span></td>'
            fi
            printf '<td class="dim"><a href="/cgi-bin/device?net=%s&mac=%s">%s</a></td>' \
                "$(_html "$_iface")" "$(_html "$_mac")" \
                "$(_html "$_mac")"
            [ "$_hdr_sig" = yes ] && printf '<td>%s</td>' "${_sig:----}"
            [ "$_hdr_bw"  = yes ] && printf '<td>%s</td>' "${_bw:----}"
            printf '<td>%s</td></tr>\n' "$([ "${_exp_ts:-0}" -gt 0 ] 2>/dev/null && _exp_str "$_exp_ts" || echo "—")"
        done
        printf '</table>\n'
    fi

    # ── Join decision history ────────────────────────────────────────────────

    if [ "${JOIN_APPROVAL:-no}" = yes ]; then
        _history="${BASE_DIR}/${_iface}-join-history"
        type _join_history_prune >/dev/null 2>&1 \
            && _join_history_prune "$_iface" "${JOIN_HISTORY_RETENTION:-90d}"
        if [ -s "$_history" ]; then
            printf '<h2 style="margin-top:1.25rem">Join history — %s</h2>' "$(_html "$_iface")"
            printf '<table><tr><th>When</th><th>Decision</th><th>Label</th><th>IP</th><th>MAC</th><th>By</th></tr>\n'
            awk -v iface="$_iface" -v lf="${BASE_DIR}/${_iface}-device-labels" -F'\t' '
            function h(s,  t){t=s;gsub(/&/,"\\&amp;",t);gsub(/</,"\\&lt;",t);gsub(/>/,"\\&gt;",t);gsub(/"/,"\\&quot;",t);return t}
            BEGIN{
                while((getline ln<lf)>0){split(ln,a,"\t");lab[tolower(a[1])]=a[2]}
                bcls["approved"]="approved";bcls["denied"]="denied";bcls["revoked"]="revoked"
                bcls["connected"]="connected";bcls["disconnected"]="disconnected"
                blbl["approved"]="Approved";blbl["denied"]="Denied";blbl["revoked"]="Revoked"
                blbl["connected"]="Connected";blbl["disconnected"]="Disconnected"
            }
            {n++;rw[n]=$2;ra[n]=$3;rm[n]=$4;ri4[n]=$5;ri6[n]=$6;rh[n]=$7;rac[n]=$8;rami[n]=$9;rami6[n]=$10;rmac[n]=$11}
            END{
                s=(n>20)?n-19:1
                for(i=s;i<=n;i++){
                    act=ra[i];when=rw[i];dmac=rm[i];ip4=ri4[i];ip6=ri6[i];host=rh[i]
                    actor=rac[i];amac=rmac[i];aip4=rami[i];aip6=rami6[i]
                    if(actor==""&&host!="")actor=host
                    cls=(act in bcls)?bcls[act]:"untracked"
                    lbl=(act in blbl)?blbl[act]:h(act)
                    lkey=tolower(dmac)
                    hlabel=(lkey in lab)?lab[lkey]:((host!=""&&host!="unknown")?host:dmac)
                    hip=(ip4!="")?ip4:(ip6!="")?ip6:"—"
                    if(amac!="")by="<a href=\"/cgi-bin/device?net=lan&mac="h(amac)"\">"h(amac)"</a>"
                    else by=h(actor!=""?actor:"unknown")
                    printf "<tr><td class=\"dim\">%s</td><td><span class=\"badge badge-%s\">%s</span></td><td><a href=\"/cgi-bin/device?net=%s&mac=%s\">%s</a></td><td>%s</td><td class=\"dim\"><a href=\"/cgi-bin/device?net=%s&mac=%s\">%s</a></td><td class=\"dim\">%s</td></tr>\n",\
                        h(when),cls,lbl,iface,h(dmac),h(hlabel),h(hip),iface,h(dmac),h(dmac),by
                }
            }' "$_history" 2>/dev/null
            printf '</table>\n'
        fi
    fi

    # ── Pending LAN access requests ───────────────────────────────────────────
    # Show attempts from this network TO the LAN with no active allow rule.
    # The 2LAN monitor is installed when LAN_ACCESS≠yes.

    _2lan_lines=$(printf '%s\n' "$_logdata" | grep "EXTNET-2LAN-${_iface}:")
    if [ -n "$_2lan_lines" ]; then
        _tmp_pending="/tmp/status_cgi_pending_${_iface}"
        rm -f "$_tmp_pending"

        printf '%s\n' "$_2lan_lines" \
            | awk '{
                src=""; dst=""; port=""; proto=""
                for(i=1;i<=NF;i++){
                    if($i~/^SRC=/) { sub(/SRC=/,"",$i); src=$i }
                    if($i~/^DST=/) { sub(/DST=/,"",$i); dst=$i }
                    if($i~/^PROTO=/) { sub(/PROTO=/,"",$i); proto=tolower($i) }
                    if($i~/^DPT=/) { sub(/DPT=/,"",$i); port=$i }
                }
                if(src && dst && port && proto)
                    printf "%s\t%s\t%s\t%s\t%s\n", $4, src, dst, port, proto
            }' \
            | sort -t "$(printf '\t')" -u -k3,5 \
            | tail -10 \
            | while IFS=$(printf '\t') read -r _ts _src _dst _port _proto; do
                [ -z "$_dst" ] && continue
                _dst_slug=$(printf '%s' "$_dst" | sed 's/[.:]/\_/g')
                _rule_key="allow_${_iface}_lan_${_dst_slug}_${_port}_${_proto}"
                uci -q get firewall."$_rule_key" >/dev/null 2>&1 && continue
                _src_name=$(_name_for_ip "$_src")
                _dst_name=$(_name_for_ip "$_dst")
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s/%s</td><td>' \
                    "$_ts" \
                    "$(_html "${_src_name:-$_src}")" \
                    "$(_html "${_dst_name:-$_dst}")" \
                    "$_port" "$_proto"
                printf '<form method="POST" action="/cgi-bin/approve-access">'
                printf '<input type="hidden" name="net" value="%s">'        "$(_html "$_iface")"
                printf '<input type="hidden" name="src" value="%s">'        "$_src"
                printf '<input type="hidden" name="dst" value="%s">'        "$_dst"
                printf '<input type="hidden" name="proto" value="%s">'      "$_proto"
                printf '<input type="hidden" name="port" value="%s">'       "$_port"
                printf '<input type="hidden" name="dest_zone" value="lan">'
                printf '<input type="hidden" name="duration" value="%s">'   "${DEFAULT_DURATION:-24h}"
                printf '<button type="submit">Grant</button>'
                printf '</form></td></tr>\n'
            done >> "$_tmp_pending" 2>/dev/null

        if [ -s "$_tmp_pending" ]; then
            printf '<h2 style="margin-top:1.25rem">Pending — %s</h2>' "$(_html "$_iface")"
            printf '<table><tr><th>Time</th><th>From (guest)</th><th>To (LAN)</th><th>Port/Proto</th><th></th></tr>\n'
            cat "$_tmp_pending"
            printf '</table>\n'
        fi
        rm -f "$_tmp_pending"
    fi

    # ── Active LAN access rules ───────────────────────────────────────────────

    _rules=""
    for _s in $(uci show firewall 2>/dev/null \
                | awk -F= '/^firewall\.allow_(lan_'"$_iface"'|'"$_iface"'_lan)/ {gsub(/\..*/,"",$1);print $1}' \
                | sort -u | sed 's/^firewall\.//'); do
        _di=$(uci -q get firewall."$_s".dest_ip   2>/dev/null || true)
        _dp=$(uci -q get firewall."$_s".dest_port 2>/dev/null || true)
        _pr=$(uci -q get firewall."$_s".proto     2>/dev/null || true)
        _ex=$(printf '%s\n' "$_crontab" \
            | awk -v r="$_s" '$0~"# "r{print $2":"$1" "$4"/"$3;exit}')
        _rules="${_rules}${_di}	${_dp}/${_pr}	${_ex:-permanent}
"
    done
    if [ -n "$_rules" ]; then
        printf '<h2 style="margin-top:1.25rem">LAN access — %s</h2>' "$(_html "$_iface")"
        printf '<table><tr><th>Device</th><th>Port/Proto</th><th>Expires</th></tr>\n'
        printf '%s' "$_rules" | while IFS=$(printf '\t') read -r _di _pp _ex; do
            [ -z "$_di" ] && continue
            _dn=$(awk -v i="$_di" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
            printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "${_dn:+$(_html "$_dn") (}${_di}${_dn:+)}" "$_pp" "$_ex"
        done
        printf '</table>\n'
    fi

    # ── Recent blocked ────────────────────────────────────────────────────────

    _deny_lines=$(printf '%s\n' "$_logdata" | grep "EXTNET-DENY-${_iface}:" | tail -10)
    if [ -n "$_deny_lines" ]; then
        printf '<h2 style="margin-top:1.25rem">Recent blocked — %s</h2>' "$(_html "$_iface")"
        printf '<table><tr><th>Time</th><th>From (device)</th><th>To</th><th>Port/Proto</th></tr>\n'
        printf '%s\n' "$_deny_lines" | while IFS= read -r _line; do
            _ts=$(printf '%s' "$_line" | awk '{print $4}')
            _src=""; _dst=""; _port=""; _proto=""
            for _tok in $_line; do
                case "$_tok" in
                    SRC=*)   _src="${_tok#SRC=}" ;;
                    DST=*)   _dst="${_tok#DST=}" ;;
                    PROTO=*) _proto=$(printf '%s' "${_tok#PROTO=}" | tr '[:upper:]' '[:lower:]') ;;
                    DPT=*)   _port="${_tok#DPT=}" ;;
                esac
            done
            _src_name=$(awk -v i="$_src" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
            printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$_ts" \
                "$(_html "${_src_name:-$_src}")" \
                "$(_html "$_dst")" \
                "${_port:+${_port}/}${_proto}"
        done
        printf '</table>\n'
    fi
done

# ── Port forwards ──────────────────────────────────────────────────────────────

_pfwd=""
for _s in $(uci show firewall 2>/dev/null | grep '=redirect' | cut -d. -f2 | cut -d= -f1); do
    _n=$(uci -q get firewall."$_s".name      2>/dev/null || true); [ -z "$_n" ] && continue
    _z=$(uci -q get firewall."$_s".src       2>/dev/null || true)
    _p=$(uci -q get firewall."$_s".src_dport 2>/dev/null || true)
    _d=$(uci -q get firewall."$_s".dest_ip   2>/dev/null || true)
    _r=$(uci -q get firewall."$_s".proto     2>/dev/null || true)
    _e=$(printf '%s\n' "$_crontab" \
        | awk -v r="$_n" '$0~"# "r{print $2":"$1" "$4"/"$3;exit}')
    _pfwd="${_pfwd}${_n}	${_z}	${_p}	${_d}	${_r}	${_e:-permanent}
"
done
if [ -n "$_pfwd" ]; then
    printf '<h2>Port forwards</h2>'
    printf '<table><tr><th>Name</th><th>Zone</th><th>Port</th><th>→ Host</th><th>Proto</th><th>Expires</th></tr>\n'
    printf '%s' "$_pfwd" | while IFS=$(printf '\t') read -r n z p d r e; do
        [ -z "$n" ] && continue
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "$(_html "$n")" "$z" "$p" "$d" "$r" "$e"
    done
    printf '</table>\n'
fi

cat <<'SCRIPT'
<script>
(function(){
  var q=document.querySelectorAll('.qr-canvas');
  for(var i=0;i<q.length;i++){
    var el=q[i],lines=el.getAttribute('data-qr').split('|').filter(Boolean);
    if(!lines.length)continue;
    var cols=lines[0].length,rows=lines.length,mods=cols>>1;
    var cv=document.createElement('canvas');
    cv.width=mods;cv.height=rows;
    cv.style.cssText='width:120px;height:120px;image-rendering:pixelated;flex-shrink:0;border-radius:4px';
    var ctx=cv.getContext('2d');
    ctx.fillStyle='#fff';ctx.fillRect(0,0,mods,rows);
    ctx.fillStyle='#000';
    for(var y=0;y<rows;y++)
      for(var x=0;x<cols;x+=2)
        if(lines[y][x]==='#')ctx.fillRect(x>>1,y,1,1);
    el.parentNode.replaceChild(cv,el);
  }
})();
</script>
SCRIPT
printf '</body></html>\n'
