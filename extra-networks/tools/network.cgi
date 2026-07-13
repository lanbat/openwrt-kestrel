#!/bin/sh
# CGI: per-network management page — devices, history, and actions for one network.
# Installed to /www/cgi-bin/network by install.sh.
# URL: /cgi-bin/network?net=<iface>

BASE_DIR=/etc/extra-networks
[ -f "${BASE_DIR}/_lib.sh" ] && . "${BASE_DIR}/_lib.sh"

_get_param() { printf '%s' "$1" | tr '&' '\n' | grep "^${2}=" | head -1 | sed "s/^${2}=//"; }
_html()      { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }
_urldecode() {
    printf '%s' "$1" | sed 's/+/ /g' | awk '
    BEGIN { for(i=0;i<256;i++) h[sprintf("%02X",i)]=h[sprintf("%02x",i)]=sprintf("%c",i) }
    { s=$0; out=""
      while(match(s,/%[0-9A-Fa-f][0-9A-Fa-f]/)) {
        out=out substr(s,1,RSTART-1) h[substr(s,RSTART+1,2)]
        s=substr(s,RSTART+RLENGTH)
      }
      print out s }'
}

_params="${QUERY_STRING:-}"
NET=$(_urldecode "$(_get_param "$_params" net)")
HIGHLIGHT_MAC=$(_urldecode "$(_get_param "$_params" mac)" | tr 'ABCDEF' 'abcdef')
printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Invalid network</h1>'; exit 0; }

_conf="${BASE_DIR}/${NET}-notify.conf"
[ -f "$_conf" ] || { printf 'Content-Type: text/html\r\n\r\n<h1>Network not found: %s</h1>' \
    "$(_html "$NET")"; exit 0; }

unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB \
      RATE_LIMIT RATE_LIMIT_PER_DEVICE DNS_SERVER DNS_SERVER_V6 ISOLATE LAN_ACCESS DOT \
      SHOW_QR NOTIFY_JOIN JOIN_APPROVAL JOIN_HISTORY_RETENTION ROTATE_PASSWORD DESCRIPTION \
      DEVICE_CONTROL DEFAULT_DURATION MAX_DURATION REASON_REQUIRED ALLOWLIST
. "$_conf"
_iface="${IFACE_NAME:-$NET}"

now_ts=$(date +%s)
_logdata=$(logread 2>/dev/null | tail -n 500)
_crontab=$(crontab -l 2>/dev/null)

_human() {
    awk -v b="${1:-0}" 'BEGIN {
        if      (b+0 >= 1073741824) printf "%.1f GB", b/1073741824
        else if (b+0 >= 1048576)   printf "%.1f MB", b/1048576
        else if (b+0 >= 1024)      printf "%.1f KB", b/1024
        else                       printf "%d B",     b+0
    }'
}

_exp_str() {
    _rem=$(( $1 - now_ts ))
    if   [ "$_rem" -le 0 ];     then printf 'expired'
    elif [ "$_rem" -gt 86400 ]; then printf '%dd' "$(( _rem / 86400 ))"
    elif [ "$_rem" -gt 3600 ];  then printf '%dh %dm' "$(( _rem / 3600 ))" "$(( (_rem % 3600) / 60 ))"
    else                             printf '%dm' "$(( _rem / 60 ))"
    fi
}

printf 'Content-Type: text/html\r\n\r\n'

hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo router)
_ssid=$(uci -q get wireless."$_iface".ssid 2>/dev/null || true)
_up=no; ip link show "br-${_iface}" 2>/dev/null | grep -q "LOWER_UP" && _up=yes
_rx=$(nft list chain inet fw4 "${_iface}_counter" 2>/dev/null \
    | awk '/iifname.*counter/ { for(i=1;i<=NF;i++) if($i=="bytes") { print $(i+1); exit } }')
_tx=$(nft list chain inet fw4 "${_iface}_counter" 2>/dev/null \
    | awk '/oifname.*counter/ { for(i=1;i<=NF;i++) if($i=="bytes") { print $(i+1); exit } }')
_rxh=$(_human "$_rx"); _txh=$(_human "$_tx")
_wlan=$(ip link show master "br-${_iface}" 2>/dev/null \
    | awk 'NR==1{n=$2; sub(/@.*/,"",n); print n}')
_assoc=$([ -n "$_wlan" ] && iwinfo "$_wlan" assoclist 2>/dev/null || true)
_neigh6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
    | awk '!/^fe80:/ && /lladdr/{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1)"\t"$1; break}}')
_neigh_states=$({ ip neigh show dev "br-${_iface}" 2>/dev/null
                  ip -6 neigh show dev "br-${_iface}" 2>/dev/null; } \
    | awk '!/^fe80:/{print $1"\t"$NF}')
_bw_data=$(nft list set inet fw4 "${_iface}_device_bytes"  2>/dev/null)
_bw_data6=$(nft list set inet fw4 "${_iface}_device_bytes6" 2>/dev/null)
_hdr_bw=$([ -n "$_bw_data$_bw_data6" ] && echo yes || echo no)
_hdr_sig=$([ -n "$_assoc" ] && echo yes || echo no)

_join_approved_f="${BASE_DIR}/${_iface}-join-approved"
_join_pending_f="${BASE_DIR}/${_iface}-join-pending"
_join_denied_f="${BASE_DIR}/${_iface}-join-denied"
_labels_f="${BASE_DIR}/${_iface}-device-labels"
_approved_ips_f="${BASE_DIR}/${_iface}-join-approved-ips"
_device_ips_f="${BASE_DIR}/${_iface}-device-ips"

# Pre-build set of currently-connected MACs (DHCP + neigh6) for dedup
_tmp_known="/tmp/netcgi_known_${_iface}_$$"
{
    awk -v s="${SUBNET}." '$3~s{print tolower($2)}' /tmp/dhcp.leases 2>/dev/null
    printf '%s\n' "$_neigh6" | awk -F'\t' 'NF{print tolower($1)}'
} > "$_tmp_known"

cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>$(_html "$_iface")${_ssid:+ — $(_html "$_ssid")}</title>
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
.actions{display:inline-flex;gap:.25rem;align-items:center;flex-wrap:wrap}
.actions form{display:inline-flex}
.actions button{font-weight:600;padding:.22rem .55rem;border-radius:999px;
                box-shadow:0 1px 2px rgba(0,0,0,.12)}
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
.badge-connected{color:#1b5e20;background:#e8f5e9}
.badge-disconnected{color:#555;background:#eee}
.badge-deleted{color:#fff;background:#37474f}
.net-desc{color:#555;font-size:.88rem;margin:.15rem 0 1.25rem}
@keyframes hl{0%{background:#fff9c4}100%{background:transparent}}
tr.highlight td{animation:hl 2s ease-out forwards}
.qr{display:flex;align-items:stretch;gap:1rem}
.qr-info{font-size:.9rem;display:flex;flex-direction:column;flex:1;min-width:0}
.qr-info strong{margin-bottom:.2rem}
.q-lbl{font-size:.72rem;color:#888;text-transform:uppercase;letter-spacing:.04em;margin-top:.4rem}
.q-lbl:first-child{margin-top:0}
.qr-info code{background:#e8e8e8;padding:.2rem .45rem;border-radius:4px;
              word-break:break-all;font-size:.85rem;align-self:flex-start}
.qr-info form{margin-top:auto;padding-top:.6rem;text-align:right}
input[type=text]{font-size:.875rem;padding:.3rem .5rem;border:1px solid #ccc;border-radius:4px}
</style></head><body>
HTML

printf '<h1>%s%s</h1>\n' "$(_html "$_iface")" "${_ssid:+ — $(_html "$_ssid")}"
[ -n "${DESCRIPTION:-}" ] && \
    printf '<div class="net-desc">%s</div>\n' "$(_html "$DESCRIPTION")"
printf '<div class="sub"><a href="/cgi-bin/status">← Dashboard</a> &nbsp;·&nbsp; <a href="">Refresh</a></div>\n'

# ── Network config card ───────────────────────────────────────────────────────

printf '<h2>Network</h2><div class="card">\n'
printf '<div class="row"><span class="lbl">State</span><span class="val %s">%s</span></div>\n' \
    "$([ "$_up" = yes ] && echo ok || echo warn)" \
    "$([ "$_up" = yes ] && echo Up || echo Down)"
[ -n "${SUBNET:-}" ] && \
    printf '<div class="row"><span class="lbl">Subnet</span><span class="val">%s.0/24</span></div>\n' "$SUBNET"
for _p in $(ip -6 addr show "br-${_iface}" scope global 2>/dev/null | awk '/inet6/{print $2}'); do
    case "$_p" in fd*|fc*) _pl="IPv6 prefix (ULA)" ;; *) _pl="IPv6 prefix" ;; esac
    printf '<div class="row"><span class="lbl">%s</span><span class="val">%s</span></div>\n' \
        "$_pl" "$(_html "$_p")"
done
printf '<div class="row"><span class="lbl">Traffic ↓ / ↑</span><span class="val">%s / %s</span></div>\n' \
    "$_rxh" "$_txh"
if [ -n "${DNS_SERVER:-}" ]; then
    _dns_v6_str=""
    [ -n "${DNS_SERVER_V6:-}" ] && _dns_v6_str=" / $(_html "$DNS_SERVER_V6")"
    printf '<div class="row"><span class="lbl">DNS</span><span class="val">%s%s%s</span></div>\n' \
        "$(_html "$DNS_SERVER")" "$_dns_v6_str" \
        "$([ "${DOT:-no}" = yes ] && echo ' (DoT)' || true)"
fi
if [ -n "${RATE_LIMIT:-}" ] && [ "${RATE_LIMIT:-0}" != "0" ]; then
    _prd=""
    [ "${RATE_LIMIT_PER_DEVICE:-0}" != "0" ] && \
        _prd=" / $(_html "$RATE_LIMIT_PER_DEVICE") per device"
    printf '<div class="row"><span class="lbl">Rate limit</span><span class="val">%s%s</span></div>\n' \
        "$(_html "$RATE_LIMIT")" "$_prd"
fi
printf '<div class="row"><span class="lbl">LAN access</span><span class="val">%s</span></div>\n' \
    "$([ "${LAN_ACCESS:-no}" = yes ] && echo yes || echo no)"
printf '<div class="row"><span class="lbl">Isolation</span><span class="val">%s</span></div>\n' \
    "$([ "${ISOLATE:-no}" = yes ] && echo on || echo off)"
printf '<div class="row"><span class="lbl">Join approval</span><span class="val">%s</span></div>\n' \
    "$([ "${JOIN_APPROVAL:-no}" = yes ] && echo on || echo off)"
[ "${BANDWIDTH_THRESHOLD_MB:-0}" != 0 ] && \
    printf '<div class="row"><span class="lbl">Bandwidth alert</span><span class="val">%s MB/h</span></div>\n' \
        "$BANDWIDTH_THRESHOLD_MB"
printf '</div>\n'

# ── WiFi QR code ─────────────────────────────────────────────────────────────

_key=$(uci -q get wireless."$_iface".key 2>/dev/null || true)
if [ "${SHOW_QR:-no}" = yes ] && [ -n "$_key" ] && [ -n "$_ssid" ] \
        && command -v qrencode >/dev/null 2>&1; then
    _enc=$(uci -q get wireless."$_iface".encryption 2>/dev/null || true)
    case "$_enc" in sae*|psk*) _wtype=WPA ;; wep*) _wtype=WEP ;; *) _wtype=nopass ;; esac
    _qrdata=$(qrencode -t ASCII -m 2 -o - \
        "WIFI:S:${_ssid};T:${_wtype};P:${_key};;" 2>/dev/null | tr '\n' '|')
    printf '<div class="card qr"><div class="qr-canvas" data-qr="%s"></div>' "$_qrdata"
    printf '<div class="qr-info"><span class="q-lbl">SSID</span><strong>%s</strong>' \
        "$(_html "$_ssid")"
    printf '<span class="q-lbl">Password</span><code>%s</code>' "$(_html "$_key")"
    [ "${ROTATE_PASSWORD:-no}" = yes ] && \
        printf '<form method="POST" action="/cgi-bin/rotate-password"><input type="hidden" name="net" value="%s"><button class="btn-danger" type="submit" onclick="return confirm('"'"'Rotate WiFi password for %s? All connected devices will need to reconnect.'"'"')">Rotate password</button></form>' \
            "$(_html "$_iface")" "$(_html "$_iface")"
    printf '</div></div>\n'
fi

# ── Devices ───────────────────────────────────────────────────────────────────
# Shows all known devices: connected (DHCP + neigh6), offline approved, pending.

# _emit_device_row hostname ip mac expiry_ts
# Writes one <tr> to stdout. Variables from outer scope are inherited.
_emit_device_row() {
    _ehn="$1" _eip="$2" _emac="$3" _eexp="$4"
    _emac_lc=$(printf '%s' "$_emac" | tr 'ABCDEF' 'abcdef')

    _eipv6=$(printf '%s\n' "$_neigh6" \
        | awk -v m="$_emac_lc" 'tolower($1)==tolower(m){print $2; exit}')

    _eonline_cls=dim
    _ens=$(printf '%s\n' "$_neigh_states" | awk -v ip="$_eip" '$1==ip{print $2;exit}')
    [ -z "$_ens" ] && [ -n "$_eipv6" ] && \
        _ens=$(printf '%s\n' "$_neigh_states" | awk -v ip="$_eipv6" '$1==ip{print $2;exit}')
    case "$_ens" in REACHABLE|DELAY|PROBE) _eonline_cls=ok ;; esac

    _elabel=$(awk -v m="$_emac_lc" \
        'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
        "$_labels_f" 2>/dev/null || true)

    _ejoin_state=Untracked
    grep -qixF "$_emac_lc" "$_join_approved_f" 2>/dev/null && _ejoin_state=Approved
    grep -qixF "$_emac_lc" "$_join_denied_f"   2>/dev/null && _ejoin_state=Denied
    grep -qi "^${_emac_lc} " "$_join_pending_f" 2>/dev/null \
        && [ "$_ejoin_state" = Untracked ] && _ejoin_state=Pending
    _ejoin_cls=$(printf '%s' "$_ejoin_state" \
        | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')

    # Best-available IP for approve-join forms (may be stale for offline devices)
    _eapprove_ip="$_eip"
    [ -z "$_eapprove_ip" ] || [ "$_eapprove_ip" = "-" ] && _eapprove_ip="$_eipv6"
    [ -z "$_eapprove_ip" ] && \
        _eapprove_ip=$(awk -v m="$_emac_lc" 'tolower($1)==tolower(m){print $2;exit}' \
            "$_approved_ips_f" 2>/dev/null || true)
    [ -z "$_eapprove_ip" ] && \
        _eapprove_ip=$(awk -v m="$_emac_lc" 'tolower($1)==tolower(m){print $2;exit}' \
            "$_device_ips_f" 2>/dev/null || true)
    [ -z "$_eapprove_ip" ] && \
        _eapprove_ip=$(awk -v m="$_emac_lc" 'tolower($1)==tolower(m){print $2;exit}' \
            "$_join_pending_f" 2>/dev/null || true)
    _ejhost=$([ "$_ehn" != "*" ] && printf '%s' "$_ehn" || true)

    printf '<tr data-mac="%s">' "$_emac_lc"
    printf '<td style="text-align:center;padding:.5rem .15rem"><span style="display:inline-block;width:11px;height:11px;border-radius:50%%;background:%s"></span></td>' \
        "$([ "$_eonline_cls" = ok ] && printf '#2e7d32' || printf '#ccc')"

    if [ -n "$_elabel" ]; then
        printf '<td><a href="/cgi-bin/device?net=%s&mac=%s">%s</a></td>' \
            "$(_html "$_iface")" "$(_html "$_emac_lc")" "$(_html "$_elabel")"
    else
        printf '<td><form method="POST" action="/cgi-bin/approve-join" style="margin:0"><input type="hidden" name="net" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="action" value="set_label"><input type="hidden" name="redirect" value="/cgi-bin/network?net=%s"><input type="text" name="label" placeholder="Add label" maxlength="40" style="padding:.2rem .35rem;border:1px solid #ccc;border-radius:3px;font-size:.8rem"><button type="submit" style="margin-left:.2rem">Save</button></form></td>' \
            "$(_html "$_iface")" "$(_html "$_emac_lc")" "$(_html "$_iface")"
    fi

    printf '<td>%s</td>' \
        "$([ -n "$_eip" ] && [ "$_eip" != "-" ] && _html "$_eip" || printf '—')"
    printf '<td class="dim">%s</td>' "${_eipv6:----}"
    printf '<td class="dim"><a href="/cgi-bin/device?net=%s&mac=%s">%s</a></td>' \
        "$(_html "$_iface")" "$(_html "$_emac_lc")" "$(_html "$_emac_lc")"

    if [ "${JOIN_APPROVAL:-no}" = yes ]; then
        printf '<td><span class="badge badge-%s">%s</span>' "$_ejoin_cls" "$_ejoin_state"
        printf '<span class="actions" style="margin-left:.4rem">'
        if [ "$_ejoin_state" != Approved ] && [ -n "$_eapprove_ip" ]; then
            printf '<form method="POST" action="/cgi-bin/approve-join"><input type="hidden" name="net" value="%s"><input type="hidden" name="ip" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="approve"><input type="hidden" name="redirect" value="/cgi-bin/network?net=%s"><input type="text" name="label" value="%s" placeholder="Label" required maxlength="40" style="padding:.2rem .35rem;border:1px solid #ccc;border-radius:3px;font-size:.8rem"><button class="btn-ok" type="submit">Approve</button></form>' \
                "$(_html "$_iface")" "$(_html "$_eapprove_ip")" "$(_html "$_emac_lc")" \
                "$(_html "$_ejhost")" "$(_html "$_iface")" "$(_html "$_elabel")"
        fi
        if [ "$_ejoin_state" != Approved ] && [ "$_ejoin_state" != Denied ] \
                && [ -n "$_eapprove_ip" ]; then
            printf '<form method="POST" action="/cgi-bin/approve-join"><input type="hidden" name="net" value="%s"><input type="hidden" name="ip" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="host" value="%s"><input type="hidden" name="action" value="deny"><input type="hidden" name="redirect" value="/cgi-bin/network?net=%s"><button class="btn-deny" type="submit">Deny</button></form>' \
                "$(_html "$_iface")" "$(_html "$_eapprove_ip")" "$(_html "$_emac_lc")" \
                "$(_html "$_ejhost")" "$(_html "$_iface")"
        fi
        if [ "$_ejoin_state" = Approved ]; then
            printf '<form method="POST" action="/cgi-bin/device" onsubmit="return confirm('"'"'Revoke internet approval?'"'"')"><input type="hidden" name="net" value="%s"><input type="hidden" name="mac" value="%s"><input type="hidden" name="action" value="revoke_join_approval"><button class="btn-danger" type="submit">Revoke</button></form>' \
                "$(_html "$_iface")" "$(_html "$_emac_lc")"
        fi
        printf '</span></td>'
    fi

    if [ "$_hdr_bw" = yes ]; then
        _eb4=$(printf '%s\n' "$_bw_data" \
            | awk -v ip="$_eip" '$0~ip && /bytes/ \
                { for(i=1;i<=NF;i++) if($i=="bytes") {print $(i+1); exit} }')
        _eb6=0
        [ -n "$_bw_data6" ] && [ -n "$_eipv6" ] && \
            _eb6=$(printf '%s\n' "$_bw_data6" \
                | awk -v ip="$_eipv6" '$0~ip && /bytes/ \
                    { for(i=1;i<=NF;i++) if($i=="bytes") {print $(i+1); exit} }')
        _etotal=$(( ${_eb4:-0} + ${_eb6:-0} ))
        printf '<td>%s</td>' "$([ "$_etotal" -gt 0 ] && _human "$_etotal" || printf '—')"
    fi

    if [ "$_hdr_sig" = yes ]; then
        _esig=$(printf '%s\n' "$_assoc" \
            | awk -v m="$_emac_lc" 'tolower($1)==tolower(m){ print $2" dBm"; exit }')
        printf '<td>%s</td>' "${_esig:----}"
    fi

    printf '<td class="dim">%s</td>' \
        "$([ "${_eexp:-0}" -gt 0 ] 2>/dev/null && _exp_str "$_eexp" || printf '—')"
    printf '</tr>\n'
}

printf '<h2>Devices</h2>\n'
printf '<table><tr><th style="width:2rem;text-align:center;padding:.45rem .15rem"></th>'
printf '<th>Label</th><th>IPv4</th><th>IPv6</th><th>MAC</th>'
[ "${JOIN_APPROVAL:-no}" = yes ] && printf '<th>Join access</th>'
[ "$_hdr_bw"  = yes ] && printf '<th>Traffic</th>'
[ "$_hdr_sig" = yes ] && printf '<th>Signal</th>'
printf '<th>Lease expires</th></tr>\n'

# 1. Currently connected — DHCP leases on this subnet
awk -v s="${SUBNET}." '$3~s{print $4"\t"$3"\t"$2"\t"$1}' /tmp/dhcp.leases 2>/dev/null \
    | while IFS=$(printf '\t') read -r _hn _ip _mac _exp_ts; do
        [ -n "$_mac" ] || continue
        _emit_device_row "$_hn" "$_ip" "$_mac" "$_exp_ts"
    done

# 2. IPv6-only neigh devices (no DHCP lease on this subnet) — deduplicated by MAC
printf '%s\n' "$_neigh6" | awk -F'\t' 'NF && !seen[tolower($1)]++{print}' \
| while IFS=$(printf '\t') read -r _nmac _nip6; do
    [ -n "$_nmac" ] || continue
    _nmac_lc=$(printf '%s' "$_nmac" | tr 'ABCDEF' 'abcdef')
    awk -v m="$_nmac_lc" 'tolower($2)==tolower(m){exit 0} END{exit 1}' \
        /tmp/dhcp.leases 2>/dev/null && continue
    _emit_device_row "*" "-" "$_nmac_lc" "0"
done

# 3. Offline approved devices (in join-approved, not currently connected)
if [ -f "$_join_approved_f" ]; then
    while IFS= read -r _amac; do
        [ -z "$_amac" ] && continue
        _amac_lc=$(printf '%s' "$_amac" | tr 'ABCDEF' 'abcdef')
        grep -qixF "$_amac_lc" "$_tmp_known" 2>/dev/null && continue
        _emit_device_row "*" "-" "$_amac_lc" "0"
    done < "$_join_approved_f"
fi

# 4. Pending / denied devices not already shown above
if [ -f "$_join_pending_f" ]; then
    while IFS= read -r _pline; do
        [ -z "$_pline" ] && continue
        _pmac=$(printf '%s' "$_pline" | awk '{print tolower($1)}')
        _pip=$(printf '%s' "$_pline" | awk '{print $2}')
        grep -qixF "$_pmac" "$_tmp_known" 2>/dev/null && continue
        grep -qixF "$_pmac" "$_join_approved_f" 2>/dev/null && continue
        _emit_device_row "*" "$_pip" "$_pmac" "0"
    done < "$_join_pending_f"
fi

printf '</table>\n'
rm -f "$_tmp_known"

# ── Join history ──────────────────────────────────────────────────────────────

if [ "${JOIN_APPROVAL:-no}" = yes ]; then
    _history="${BASE_DIR}/${_iface}-join-history"
    type _join_history_prune >/dev/null 2>&1 \
        && _join_history_prune "$_iface" "${JOIN_HISTORY_RETENTION:-90d}"
    if [ -s "$_history" ]; then
        printf '<h2>Join history</h2>'
        printf '<table><tr><th>When</th><th>Decision</th><th>Label</th><th>IP</th><th>MAC</th><th>By</th></tr>\n'
        awk -v iface="$_iface" -v lf="${BASE_DIR}/${_iface}-device-labels" -F'\t' '
        function h(s,  t){t=s;gsub(/&/,"\\&amp;",t);gsub(/</,"\\&lt;",t);
                          gsub(/>/,"\\&gt;",t);gsub(/"/,"\\&quot;",t);return t}
        BEGIN{
            while((getline ln<lf)>0){split(ln,a,"\t");lab[tolower(a[1])]=a[2]}
            while((getline ln<"/tmp/dhcp.leases")>0){split(ln,a," ");
                if(a[3]!=""&&a[2]!="")lm[a[3]]=a[2]}
            while(("ip neigh show" | getline ln)>0){
                n2=split(ln,a," ");
                for(i=1;i<n2;i++) if(a[i]=="lladdr"){arp[a[1]]=a[i+1];break}}
            bcls["approved"]="approved";bcls["denied"]="denied";bcls["revoked"]="revoked"
            bcls["connected"]="connected";bcls["disconnected"]="disconnected"
            bcls["deleted"]="deleted"
            blbl["approved"]="Approved";blbl["denied"]="Denied";blbl["revoked"]="Revoked"
            blbl["connected"]="Connected";blbl["disconnected"]="Disconnected"
            blbl["deleted"]="Deleted"
        }
        {n++;rw[n]=$2;ra[n]=$3;rm[n]=$4;ri4[n]=$5;ri6[n]=$6;rh[n]=$7;
         rac[n]=$8;rami[n]=$9;rami6[n]=$10;rmac[n]=$11}
        END{
            s=(n>50)?n-49:1
            for(i=n;i>=s;i--){
                act=ra[i];when=rw[i];dmac=rm[i];ip4=ri4[i];ip6=ri6[i];host=rh[i]
                actor=rac[i];amac=rmac[i];aip4=rami[i]
                if(amac==""&&aip4!=""&&aip4 in lm)amac=lm[aip4]
                if(amac==""&&aip4!=""&&aip4 in arp)amac=arp[aip4]
                if(actor==""&&host!="")actor=host
                cls=(act in bcls)?bcls[act]:"untracked"
                lbl=(act in blbl)?blbl[act]:h(act)
                lkey=tolower(dmac)
                hlabel=(lkey in lab)?lab[lkey]:((host!=""&&host!="unknown")?host:dmac)
                hip=(ip4!="")?ip4:(ip6!="")?ip6:"—"
                if(amac!="")
                    by="<a href=\"/cgi-bin/device?net=lan&mac="h(amac)"\">"h(amac)"</a>"
                else
                    by=h(actor!=""?actor:"unknown")
                printf "<tr><td class=\"dim\">%s</td><td><span class=\"badge badge-%s\">%s</span></td><td><a href=\"/cgi-bin/device?net=%s&mac=%s\">%s</a></td><td>%s</td><td class=\"dim\"><a href=\"/cgi-bin/device?net=%s&mac=%s\">%s</a></td><td class=\"dim\">%s</td></tr>\n",\
                    h(when),cls,lbl,iface,h(dmac),h(hlabel),h(hip),iface,h(dmac),h(dmac),by
            }
        }' "$_history" 2>/dev/null
        printf '</table>\n'
    fi
fi

# ── Pending LAN access requests ───────────────────────────────────────────────

_2lan_lines=$(printf '%s\n' "$_logdata" | grep "EXTNET-2LAN-${_iface}:")
if [ -n "$_2lan_lines" ]; then
    _tmp_pending="/tmp/netcgi_pending_${_iface}_$$"
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
            printf '<input type="hidden" name="net"       value="%s">' "$(_html "$_iface")"
            printf '<input type="hidden" name="src"       value="%s">' "$_src"
            printf '<input type="hidden" name="dst"       value="%s">' "$_dst"
            printf '<input type="hidden" name="proto"     value="%s">' "$_proto"
            printf '<input type="hidden" name="port"      value="%s">' "$_port"
            printf '<input type="hidden" name="dest_zone" value="lan">'
            printf '<input type="hidden" name="duration"  value="%s">' \
                "${DEFAULT_DURATION:-24h}"
            printf '<button type="submit">Grant</button>'
            printf '</form></td></tr>\n'
        done >> "$_tmp_pending" 2>/dev/null
    if [ -s "$_tmp_pending" ]; then
        printf '<h2>Pending LAN access</h2>'
        printf '<table><tr><th>Time</th><th>From (guest)</th><th>To (LAN)</th><th>Port/Proto</th><th></th></tr>\n'
        cat "$_tmp_pending"
        printf '</table>\n'
    fi
    rm -f "$_tmp_pending"
fi

# ── Active LAN access rules ───────────────────────────────────────────────────

_rules=""
for _s in $(uci show firewall 2>/dev/null \
            | awk -F= '/^firewall\.allow_(lan_'"$_iface"'|'"$_iface"'_lan)/ \
                {gsub(/\..*/,"",$1);print $1}' \
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
    printf '<h2>LAN access rules</h2>'
    printf '<table><tr><th>Device</th><th>Port/Proto</th><th>Expires</th></tr>\n'
    printf '%s' "$_rules" | while IFS=$(printf '\t') read -r _di _pp _ex; do
        [ -z "$_di" ] && continue
        _dn=$(awk -v i="$_di" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
        printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "${_dn:+$(_html "$_dn") (}${_di}${_dn:+)}" "$_pp" "$_ex"
    done
    printf '</table>\n'
fi

# ── Recent blocked ────────────────────────────────────────────────────────────

_deny_lines=$(printf '%s\n' "$_logdata" | grep "EXTNET-DENY-${_iface}:" | tail -10)
if [ -n "$_deny_lines" ]; then
    printf '<h2>Recent blocked</h2>'
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
        _sname=$(awk -v i="$_src" '$3==i{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "$_ts" \
            "$(_html "${_sname:-$_src}")" \
            "$(_html "$_dst")" \
            "${_port:+${_port}/}${_proto}"
    done
    printf '</table>\n'
fi

cat <<'SCRIPT'
<script>
(function(){
  var p=new URLSearchParams(location.search),mac=p.get('mac');
  if(mac){
    var row=document.querySelector('tr[data-mac="'+mac.toLowerCase()+'"]');
    if(row){row.scrollIntoView({block:'center'});row.classList.add('highlight');}
  }
})();
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
