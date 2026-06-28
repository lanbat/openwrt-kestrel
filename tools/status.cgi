#!/bin/sh
# CGI: live status dashboard for all isolated networks.
# Installed to /www/cgi-bin/status by install.sh when NOTIFY_URL is set.
# Only reachable from LAN — isolated zones have INPUT=REJECT.

BASE_DIR=/etc/extra-networks

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
table{width:100%;border-collapse:collapse;font-size:.875rem;margin:.4rem 0}
th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;
   color:#888;padding:.35rem .5rem;border-bottom:1px solid #e0e0e0}
td{padding:.35rem .5rem;border-bottom:1px solid #f0f0f0;vertical-align:top}
a{color:#1976d2;text-decoration:none}
form{display:inline}
button{font-size:.75rem;padding:.15rem .45rem;cursor:pointer;background:#1976d2;
       color:#fff;border:none;border-radius:4px}
.btn-danger{background:#c62828}
.net-desc{color:#555;font-size:.88rem;margin:-.4rem 0 .6rem}
.qr{display:flex;align-items:stretch;gap:1rem}
.qr-info{font-size:.9rem;display:flex;flex-direction:column;flex:1;min-width:0}
.qr-info strong{display:block;margin-bottom:.3rem}
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
if [ -f "$VPN_CFG" ]; then
    unset VPN_IFACE ROUTE_TABLE FWMARK NOTIFY_URL
    . "$VPN_CFG"
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

# ── Networks ───────────────────────────────────────────────────────────────────

for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB \
          RATE_LIMIT RATE_LIMIT_PER_DEVICE DNS_SERVER ISOLATE LAN_ACCESS DOT \
          SHOW_QR NOTIFY_JOIN ROTATE_PASSWORD DESCRIPTION
    . "$_conf"
    _iface="${IFACE_NAME:-}"
    [ -z "$_iface" ] && continue

    _ssid=$(uci -q get wireless."$_iface".ssid 2>/dev/null || true)
    _up=no; ip link show "br-${_iface}" 2>/dev/null | grep -q "LOWER_UP" && _up=yes
    _rx=$(_nft_bytes "${_iface}_counter" in);  _rxh=$(_human "$_rx")
    _tx=$(_nft_bytes "${_iface}_counter" out); _txh=$(_human "$_tx")
    _devs=$(awk -v s="${SUBNET}." '$3~s{print $4"\t"$3"\t"$2"\t"$1}' /tmp/dhcp.leases 2>/dev/null)
    _dc=$(printf '%s\n' "$_devs" | awk 'NF{c++}END{print c+0}')

    # WiFi interface for signal strength (e.g. phy0-ap1 for br-guest)
    _wlan=$(ip link show master "br-${_iface}" 2>/dev/null \
        | awk 'NR==1{n=$2; sub(/@.*/,"",n); print n}')
    _assoc=$([ -n "$_wlan" ] && iwinfo "$_wlan" assoclist 2>/dev/null || true)

    # IPv6 neighbour table for this bridge: MAC → global/ULA address (skip link-local)
    _neigh6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
        | awk '!/^fe80:/ && /lladdr/{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1)"\t"$1; break}}')

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
    _ipv6_prefix=$(ip -6 addr show "br-${_iface}" scope global 2>/dev/null \
        | awk '/inet6/{print $2; exit}')
    [ -n "$_ipv6_prefix" ] && \
        printf '<div class="row"><span class="lbl">IPv6 prefix</span><span class="val">%s</span></div>' \
            "$(_html "$_ipv6_prefix")"
    printf '<div class="row"><span class="lbl">Traffic ↓ / ↑</span><span class="val">%s / %s</span></div>' \
        "$_rxh" "$_txh"
    printf '<div class="row"><span class="lbl">Devices</span><span class="val">%s</span></div>' "$_dc"
    [ -n "${DNS_SERVER:-}" ] && \
        printf '<div class="row"><span class="lbl">DNS</span><span class="val">%s%s</span></div>' \
            "$(_html "$DNS_SERVER")" \
            "$([ "${DOT:-no}" = yes ] && echo ' (DoT)' || true)"
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
        printf '<div class="card qr"><div class="qr-canvas" data-qr="%s"></div><div class="qr-info"><strong>%s</strong><code>%s</code>' \
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
        _hdr_bw=$([ -n "$_bw_data$_bw_data6" ] && echo yes || echo no)
        _hdr_sig=$([ -n "$_assoc" ] && echo yes || echo no)
        _hdr_ip6=$([ -n "$_neigh6" ] && echo yes || echo no)

        printf '<table><tr><th>Hostname</th><th>IPv4</th>'
        [ "$_hdr_ip6" = yes ] && printf '<th>IPv6</th>'
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

            printf '<tr><td>%s</td><td>%s</td>' "$(_html "$_hn")" "$_ip"
            [ "$_hdr_ip6" = yes ] && printf '<td class="dim">%s</td>' "${_ipv6:----}"
            printf '<td class="dim">%s</td>' "$_mac"
            [ "$_hdr_sig" = yes ] && printf '<td>%s</td>' "${_sig:----}"
            [ "$_hdr_bw"  = yes ] && printf '<td>%s</td>' "${_bw:----}"
            printf '<td>%s</td></tr>\n' "$(_exp_str "$_exp_ts")"
        done
        printf '</table>\n'
    fi

    # ── Pending LAN access requests ───────────────────────────────────────────
    # Show LAN→network attempts with no active allow rule; inline Grant form.
    # LAN2 monitor is only installed when LAN_ACCESS≠yes, so this is only
    # meaningful for networks with restricted LAN access.

    _lan2_lines=$(printf '%s\n' "$_logdata" | grep "EXTNET-LAN2${_iface}:")
    if [ -n "$_lan2_lines" ]; then
        _tmp_pending="/tmp/status_cgi_pending_${_iface}"
        rm -f "$_tmp_pending"

        printf '%s\n' "$_lan2_lines" \
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
                _dst_slug=$(printf '%s' "$_dst" | tr '.' '_')
                _rule_key="allow_lan_${_iface}_${_dst_slug}_${_port}_${_proto}"
                uci -q get firewall."$_rule_key" >/dev/null 2>&1 && continue
                _src_name=$(awk -v i="$_src" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
                _dst_name=$(awk -v i="$_dst" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s/%s</td><td>' \
                    "$_ts" \
                    "$(_html "${_src_name:-$_src}")" \
                    "$(_html "${_dst_name:-$_dst}")" \
                    "$_port" "$_proto"
                printf '<form method="POST" action="/cgi-bin/approve-access">'
                printf '<input type="hidden" name="net" value="%s">'   "$(_html "$_iface")"
                printf '<input type="hidden" name="src" value="%s">'   "$_src"
                printf '<input type="hidden" name="dst" value="%s">'   "$_dst"
                printf '<input type="hidden" name="proto" value="%s">' "$_proto"
                printf '<input type="hidden" name="port" value="%s">'  "$_port"
                printf '<input type="hidden" name="duration" value="%s">' "${DEFAULT_DURATION:-24h}"
                printf '<button type="submit">Grant</button>'
                printf '</form></td></tr>\n'
            done >> "$_tmp_pending" 2>/dev/null

        if [ -s "$_tmp_pending" ]; then
            printf '<h2 style="margin-top:1.25rem">Pending — %s</h2>' "$(_html "$_iface")"
            printf '<table><tr><th>Time</th><th>From (LAN)</th><th>To (device)</th><th>Port/Proto</th><th></th></tr>\n'
            cat "$_tmp_pending"
            printf '</table>\n'
        fi
        rm -f "$_tmp_pending"
    fi

    # ── Active LAN access rules ───────────────────────────────────────────────

    _rules=""
    for _s in $(uci show firewall 2>/dev/null \
                | awk -F= '/^firewall\.allow_lan_'"$_iface"'/ {gsub(/\..*/,"",$1);print $1}' \
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
