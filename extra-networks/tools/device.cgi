#!/bin/sh
# CGI: per-device control page for isolated networks with DEVICE_CONTROL=yes.

BASE_DIR=/etc/extra-networks
. "${BASE_DIR}/_lib.sh"

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
_valid_ip()  {
    case "$1" in
        *.*.*.*)  printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' ;;
        *:*)      printf '%s' "$1" | grep -qE '^[0-9a-fA-F:]{2,39}$' ;;
        *)        return 1 ;;
    esac
}
_upsert() {
    # _upsert file mac value — replace MAC line or append
    { grep -v "^${2}	" "$1" 2>/dev/null; printf '%s\t%s\n' "$2" "$3"; } \
        > "${1}.tmp" && mv "${1}.tmp" "$1" || true
}

# CSRF
if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _origin="${HTTP_ORIGIN:-${HTTP_REFERER:-}}"
    case "$_origin" in
        ""|http://192.168.*|http://10.*|http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) ;;
        http://\[fd*|http://\[fc*|http://\[fe80*|http://\[::1\]*) ;;
        *) printf 'Content-Type: text/html\r\n\r\nForbidden'; exit 0 ;;
    esac
fi

# Parse params
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ -n "${CONTENT_LENGTH:-}" ]; then
    printf '%s' "$CONTENT_LENGTH" | grep -qE '^[0-9]+$' && [ "$CONTENT_LENGTH" -le 4096 ] \
        || { printf 'Content-Type: text/html\r\n\r\nBad request'; exit 0; }
    _params=$(head -c "$CONTENT_LENGTH")
    [ -n "${QUERY_STRING:-}" ] && _params="${QUERY_STRING}&${_params}"
else
    _params="${QUERY_STRING:-}"
fi

NET=$(_urldecode "$(_get_param "$_params" net)")
MAC=$(_urldecode "$(_get_param "$_params" mac)" | tr 'ABCDEF' 'abcdef')

printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Invalid network</h1>'; exit 0; }
printf '%s' "$MAC" | grep -qE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Invalid MAC</h1>'; exit 0; }

_load_notify "$NET"
_iface="${IFACE_NAME:-$NET}"
_mac_n=$(printf '%s' "$MAC" | tr -d ':')

_labels_f="${BASE_DIR}/${_iface}-device-labels"
_ips_f="${BASE_DIR}/${_iface}-device-ips"
_limits_f="${BASE_DIR}/${_iface}-device-limits"
_rules_f="${BASE_DIR}/${_iface}-device-rules"
_pending_f="${BASE_DIR}/${_iface}-pending-${_mac_n}"
_join_approved_f="${BASE_DIR}/${_iface}-join-approved"
_join_pending_f="${BASE_DIR}/${_iface}-join-pending"
_join_denied_f="${BASE_DIR}/${_iface}-join-denied"

_DEV_LABEL=$(awk -v m="$MAC" 'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
    "$_labels_f" 2>/dev/null || true)
_DEV_IP=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' \
    "$_ips_f" 2>/dev/null || true)
_DEV_LIMIT=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' \
    "$_limits_f" 2>/dev/null || true)
_DEV_LIMIT="${_DEV_LIMIT:-120}"
_DEV_DISPLAY="${_DEV_LABEL:-$MAC}"
_BACK_URL="/cgi-bin/device?net=${NET}&mac=${MAC}"

# ── POST actions ──────────────────────────────────────────────────────────────

if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _action=$(_get_param "$_params" action)
    printf 'Content-Type: text/html\r\n\r\n'

    case "$_action" in

    set_label)
        _new=$(printf '%s' "$(_get_param "$_params" label)" \
            | sed 's/+/ /g;s/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 40)
        _safe=$(printf '%s' "$_new" | sed "s/[^a-zA-Z0-9 _.'-]//g")
        [ -n "$_safe" ] && { mkdir -p "$BASE_DIR"; _upsert "$_labels_f" "$MAC" "$_safe"; }
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    set_limit)
        _lim=$(_get_param "$_params" limit)
        { printf '%s' "$_lim" | grep -qE '^[0-9]+$' \
            && [ "$_lim" -ge 1 ] 2>/dev/null && [ "$_lim" -le 9999 ] 2>/dev/null; } \
            || { printf '<h1>Invalid limit</h1>'; exit 0; }
        _upsert "$_limits_f" "$MAC" "$_lim"
        setsid sh /etc/extra-networks/_regen-inspect.sh "$_iface" >/dev/null 2>&1 &
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    revoke_join_approval)
        _approver_ip="${REMOTE_ADDR:-unknown}"
        _approver_name=$(_name_for_ip "$_approver_ip")
        _approver_mac=$(_mac_for_ip "$_approver_ip")
        _approver="${_approver_name:-$_approver_ip}"
        [ "$_approver" = "*" ] && _approver="$_approver_ip"
        [ -n "$_approver_mac" ] && _approver="${_approver}, MAC: ${_approver_mac}"
        _dns=$([ -n "$_DEV_IP" ] && nslookup "$_DEV_IP" 2>/dev/null | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}' || true)
        _device_detail="IP: ${_DEV_IP:-unknown}
DNS: ${_dns:-unknown}
Hostname: ${_DEV_LABEL:-unknown}
MAC: ${MAC}"
        [ -f "$_join_approved_f" ] && {
            grep -vixF "$MAC" "$_join_approved_f" > "${_join_approved_f}.tmp" 2>/dev/null \
                && mv "${_join_approved_f}.tmp" "$_join_approved_f" || true
        }
        if [ -n "$_DEV_IP" ]; then
            { grep -vi "^${MAC} " "$_join_pending_f" 2>/dev/null; printf '%s %s\n' "$MAC" "$_DEV_IP"; } \
                > "${_join_pending_f}.tmp" && mv "${_join_pending_f}.tmp" "$_join_pending_f" || true
            nft add element inet fw4 "${_iface}_join_pending" "{ ${_DEV_IP} }" 2>/dev/null || true
        fi
        { grep -vixF "$MAC" "$_join_denied_f" 2>/dev/null; } \
            > "${_join_denied_f}.tmp" && mv "${_join_denied_f}.tmp" "$_join_denied_f" || true
        _join_history_add "$_iface" revoked "$MAC" "${_DEV_IP:-unknown}" "${_DEV_LABEL:-${_dns:-unknown}}" "$_approver" "${JOIN_HISTORY_RETENTION:-90d}"
        _ntfy "Access revoked — ${_iface}" default no_entry \
"Type: Internet access revoked

Revoked device:
${_device_detail}
Revoked by: ${_approver}

The device is no longer approved on ${_iface}."
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    approve_domain)
        _dom=$(printf '%s' "$(_get_param "$_params" domain)" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
            | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
        printf '%s' "$_dom" | grep -qE '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' \
            || { printf '<h1>Invalid domain</h1>'; exit 0; }
        _entry="${MAC}	${_dom}	allow		"
        grep -qF "$_entry" "$_rules_f" 2>/dev/null \
            || printf '%s\n' "$_entry" >> "$_rules_f"
        _dconf="/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
        _nftset="4#inet#fw4#${_iface}_allow_${_mac_n}_4,6#inet#fw4/${_iface}_allow_${_mac_n}_6"
        _dentry="nftset=/${_dom}/${_nftset}"
        grep -qF "$_dentry" "$_dconf" 2>/dev/null \
            || printf '%s\n' "$_dentry" >> "$_dconf"
        /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
        _ntfy "Rule added — ${_iface}" default shield \
            "${_DEV_DISPLAY}: ${_dom} allowed on ${_iface}."
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    approve_pending)
        _dip=$(_get_param "$_params" dst_ip)
        _dpt=$(_get_param "$_params" dst_port)
        _dpr=$(_get_param "$_params" dst_proto)
        _valid_ip "$_dip" || { printf '<h1>Invalid IP</h1>'; exit 0; }
        printf '%s' "$_dpt" | grep -qE '^[0-9]{1,5}$' \
            || { printf '<h1>Invalid port</h1>'; exit 0; }
        printf '%s' "$_dpr" | grep -qE '^(tcp|udp|icmp)$' \
            || { printf '<h1>Invalid proto</h1>'; exit 0; }
        _entry="${MAC}	${_dip}	allow	${_dpt}	${_dpr}"
        grep -qF "$_entry" "$_rules_f" 2>/dev/null \
            || printf '%s\n' "$_entry" >> "$_rules_f"
        nft add element inet fw4 "${_iface}_allow_${_mac_n}_4" "{ ${_dip} }" 2>/dev/null || true
        [ -f "$_pending_f" ] && {
            grep -v "^${_dip}	${_dpt}	${_dpr}	" "$_pending_f" \
                > "${_pending_f}.tmp" 2>/dev/null \
                && mv "${_pending_f}.tmp" "$_pending_f" || true
        }
        _ntfy "Rule added — ${_iface}" default shield \
            "${_DEV_DISPLAY}: ${_dip}:${_dpt}/${_dpr} allowed on ${_iface}."
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    deny_pending)
        _dip=$(_get_param "$_params" dst_ip)
        _dpt=$(_get_param "$_params" dst_port)
        _dpr=$(_get_param "$_params" dst_proto)
        _valid_ip "$_dip" || { printf '<h1>Invalid IP</h1>'; exit 0; }
        [ -f "$_pending_f" ] && {
            grep -v "^${_dip}	${_dpt}	${_dpr}	" "$_pending_f" \
                > "${_pending_f}.tmp" 2>/dev/null \
                && mv "${_pending_f}.tmp" "$_pending_f" || true
        }
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    revoke_rule)
        _dst=$(_get_param "$_params" dst)
        _port=$(_get_param "$_params" port)
        _proto=$(_get_param "$_params" proto)
        [ -f "$_rules_f" ] && {
            grep -v "^${MAC}	${_dst}	" "$_rules_f" \
                > "${_rules_f}.tmp" 2>/dev/null \
                && mv "${_rules_f}.tmp" "$_rules_f" || true
        }
        case "$_dst" in
            *.*.*.*)
                nft delete element inet fw4 "${_iface}_allow_${_mac_n}_4" \
                    "{ ${_dst} }" 2>/dev/null || true
                ;;
            *)
                _dconf="/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
                [ -f "$_dconf" ] && {
                    grep -v "/${_dst}/" "$_dconf" > "${_dconf}.tmp" 2>/dev/null \
                        && mv "${_dconf}.tmp" "$_dconf" || true
                }
                /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
                ;;
        esac
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    esac
    printf '<h1>Unknown action</h1>'
    exit 0
fi

# ── GET: render page ──────────────────────────────────────────────────────────

# Scrape logread for new pending connections from this device
if [ -n "$_DEV_IP" ]; then
    _now_ts=$(date +%s)
    logread 2>/dev/null \
    | awk -v ip="$_DEV_IP" -v iface="$_iface" \
        'index($0, "EXTNET-" iface "-NEW:") {
            src=""; dst=""; dpt=""; proto=""
            for(i=1;i<=NF;i++){
                if($i~/^SRC=/) { sub(/^SRC=/,"",$i); src=$i }
                if($i~/^DST=/) { sub(/^DST=/,"",$i); dst=$i }
                if($i~/^DPT=/) { sub(/^DPT=/,"",$i); dpt=$i }
                if($i~/^PROTO=/) { sub(/^PROTO=/,"",$i); proto=tolower($i) }
            }
            if(src==ip && dst && dpt && proto) print dst"\t"dpt"\t"proto
        }' \
    | sort -u -t "$(printf '\t')" -k1,3 \
    | while IFS=$(printf '\t') read -r _dst _dpt _proto; do
        grep -qF "${MAC}	${_dst}	" "$_rules_f" 2>/dev/null && continue
        _key="${_dst}	${_dpt}	${_proto}"
        grep -qF "${_key}	" "$_pending_f" 2>/dev/null \
            || printf '%s\t%s\n' "$_key" "$_now_ts" >> "$_pending_f" 2>/dev/null || true
    done
fi

_is_approved=no
grep -qF "$MAC" "${BASE_DIR}/${_iface}-join-approved" 2>/dev/null && _is_approved=yes

# Build pending rows
_pending_rows=$([ -f "$_pending_f" ] && \
    while IFS=$(printf '\t') read -r _dst _dpt _proto _ts; do
        [ -z "$_dst" ] && continue
        grep -qF "${MAC}	${_dst}	" "$_rules_f" 2>/dev/null && continue
        _rdns=$(nslookup "$_dst" 2>/dev/null \
            | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}')
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td class="dim">%s</td><td>' \
            "$(_html "$_dst")" "$_dpt" "$_proto" "$(_html "${_rdns:----}")"
        printf '<form method="POST" action="/cgi-bin/device">'
        printf '<input type="hidden" name="net"       value="%s">' "$(_html "$NET")"
        printf '<input type="hidden" name="mac"       value="%s">' "$(_html "$MAC")"
        printf '<input type="hidden" name="action"    value="approve_pending">'
        printf '<input type="hidden" name="dst_ip"    value="%s">' "$(_html "$_dst")"
        printf '<input type="hidden" name="dst_port"  value="%s">' "$(_html "$_dpt")"
        printf '<input type="hidden" name="dst_proto" value="%s">' "$(_html "$_proto")"
        printf '<button type="submit">Allow</button></form> '
        printf '<form method="POST" action="/cgi-bin/device">'
        printf '<input type="hidden" name="net"       value="%s">' "$(_html "$NET")"
        printf '<input type="hidden" name="mac"       value="%s">' "$(_html "$MAC")"
        printf '<input type="hidden" name="action"    value="deny_pending">'
        printf '<input type="hidden" name="dst_ip"    value="%s">' "$(_html "$_dst")"
        printf '<input type="hidden" name="dst_port"  value="%s">' "$(_html "$_dpt")"
        printf '<input type="hidden" name="dst_proto" value="%s">' "$(_html "$_proto")"
        printf '<button class="btn-danger" type="submit">Deny</button></form>'
        printf '</td></tr>\n'
    done < "$_pending_f" 2>/dev/null \
|| true)

# Build rules rows
_rules_rows=$([ -f "$_rules_f" ] && \
    awk -v m="$MAC" -F'\t' 'tolower($1)==tolower(m) && NF>=3{print}' \
        "$_rules_f" 2>/dev/null \
    | while IFS=$(printf '\t') read -r _rmac _rdst _ract _rport _rproto; do
        [ -z "$_rdst" ] && continue
        _tc=$([ "$_ract" = allow ] && echo "tag-allow" || echo "tag-deny")
        _tl=$([ "$_ract" = allow ] && echo "Allow" || echo "Deny")
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td class="%s">%s</td><td>' \
            "$(_html "$_rdst")" "${_rport:----}" "${_rproto:----}" "$_tc" "$_tl"
        printf '<form method="POST" action="/cgi-bin/device">'
        printf '<input type="hidden" name="net"   value="%s">' "$(_html "$NET")"
        printf '<input type="hidden" name="mac"   value="%s">' "$(_html "$MAC")"
        printf '<input type="hidden" name="action" value="revoke_rule">'
        printf '<input type="hidden" name="dst"   value="%s">' "$(_html "$_rdst")"
        printf '<input type="hidden" name="port"  value="%s">' "$(_html "${_rport:-}")"
        printf '<input type="hidden" name="proto" value="%s">' "$(_html "${_rproto:-}")"
        printf '<button class="btn-danger" type="submit">Revoke</button></form>'
        printf '</td></tr>\n'
    done \
|| true)

_approval_row=""
if [ "$_is_approved" = yes ]; then
    _approval_row=$(cat <<HTML
<div class="row"><span class="lbl">Approval</span><span class="val">
<form method="POST" action="/cgi-bin/device" onsubmit="return confirm('Revoke internet approval for $(_html "$_DEV_DISPLAY")?')">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="action" value="revoke_join_approval">
<button class="btn-danger" type="submit">Revoke approval</button>
</form>
</span></div>
HTML
)
fi

printf 'Content-Type: text/html\r\n\r\n'

cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device — $(_html "$_DEV_DISPLAY")</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:1rem;color:#111}
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
.btn-ok{background:#2e7d32}
.btn-danger{background:#c62828}
input[type=text],input[type=number]{font-size:.875rem;padding:.3rem .5rem;
   border:1px solid #ccc;border-radius:4px}
.irow{display:flex;gap:.5rem;align-items:center;margin:.4rem 0}
.tag-allow{color:#2e7d32;font-weight:600}.tag-deny{color:#c62828;font-weight:600}
</style></head><body>
<h1>$(_html "$_DEV_DISPLAY")</h1>
<div class="sub">$(_html "$_iface") &nbsp;·&nbsp; $(_html "$MAC") &nbsp;·&nbsp; <a href="/cgi-bin/status">Dashboard</a></div>

<h2>Device</h2>
<div class="card">
<div class="row"><span class="lbl">MAC</span><span class="val">$(_html "$MAC")</span></div>
<div class="row"><span class="lbl">Tracked IP</span><span class="val">${_DEV_IP:----}</span></div>
<div class="row"><span class="lbl">Network</span><span class="val">$(_html "$_iface")</span></div>
<div class="row"><span class="lbl">Join approval</span><span class="val $([ "$_is_approved" = yes ] && echo ok || echo warn)">$([ "$_is_approved" = yes ] && echo Approved || echo Pending)</span></div>
${_approval_row}
</div>

<h2>Label</h2>
<form method="POST" action="/cgi-bin/device">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="action" value="set_label">
<div class="irow">
<input type="text" name="label" value="$(_html "$_DEV_LABEL")" maxlength="40" placeholder="Device name" style="width:220px">
<button type="submit">Save</button>
</div>
</form>

<h2>Connection rate limit</h2>
<form method="POST" action="/cgi-bin/device">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="action" value="set_limit">
<div class="irow">
<input type="number" name="limit" value="$(_html "$_DEV_LIMIT")" min="1" max="9999" style="width:80px">
<span style="font-size:.85rem;color:#666">new connections / minute</span>
<button type="submit">Save</button>
</div>
</form>

<h2>Approve domain</h2>
<form method="POST" action="/cgi-bin/device">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="action" value="approve_domain">
<div class="irow">
<input type="text" name="domain" placeholder="api.example.com" maxlength="253" style="width:220px">
<button type="submit">Allow</button>
</div>
</form>

<h2>Pending connections</h2>
HTML

if [ -n "$_pending_rows" ]; then
    printf '<table><tr><th>Destination</th><th>Port</th><th>Proto</th><th>Hostname</th><th></th></tr>\n'
    printf '%s\n' "$_pending_rows"
    printf '</table>\n'
else
    printf '<p class="dim">No pending connections.</p>\n'
fi

printf '<h2>Rules</h2>\n'
if [ -n "$_rules_rows" ]; then
    printf '<table><tr><th>Destination</th><th>Port</th><th>Proto</th><th>Action</th><th></th></tr>\n'
    printf '%s\n' "$_rules_rows"
    printf '</table>\n'
else
    printf '<p class="dim">No rules yet.</p>\n'
fi

printf '</body></html>\n'
