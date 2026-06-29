#!/bin/sh
# CGI: approve or deny internet access for a device that just joined an isolated network.
# Installed to /www/cgi-bin/approve-join by install.sh when NOTIFY_URL is set.
# Only reachable from LAN — isolated zones have INPUT=REJECT.

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

# CSRF: reject POSTs whose Origin/Referer is not a private address
if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _origin="${HTTP_ORIGIN:-${HTTP_REFERER:-}}"
    case "$_origin" in
        ""|http://192.168.*|http://10.*|http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) ;;
        http://\[fd*|http://\[fc*|http://\[fe80*|http://\[::1\]*) ;;
        *) printf 'Content-Type: text/html\r\n\r\nForbidden'; exit 0 ;;
    esac
fi

# Parse parameters
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ -n "${CONTENT_LENGTH:-}" ]; then
    printf '%s' "$CONTENT_LENGTH" | grep -qE '^[0-9]+$' && [ "$CONTENT_LENGTH" -le 2048 ] \
        || { printf 'Content-Type: text/html\r\n\r\nBad request'; exit 0; }
    _params=$(head -c "$CONTENT_LENGTH")
    [ -n "${QUERY_STRING:-}" ] && _params="${QUERY_STRING}&${_params}"
else
    _params="${QUERY_STRING:-}"
fi

NET=$(_urldecode "$(_get_param "$_params" net)")
IP=$(_urldecode "$(_get_param  "$_params" ip)")
MAC=$(_urldecode "$(_get_param "$_params" mac)" | tr 'ABCDEF' 'abcdef')
HOST=$(_urldecode "$(_get_param "$_params" host)")

printf 'Content-Type: text/html\r\n\r\n'

# Validate inputs
printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' || { printf '<h1>Invalid network</h1>'; exit 0; }
_valid_ip "$IP"                                      || { printf '<h1>Invalid IP</h1>'; exit 0; }
printf '%s' "$MAC" | grep -qiE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
    || { printf '<h1>Invalid MAC</h1>'; exit 0; }

_load_notify "$NET"
[ -n "${NOTIFY_URL:-}" ] \
    || { printf '<h1>Notifications not configured for %s</h1>' "$(_html "$NET")"; exit 0; }

APPROVED_FILE="${BASE_DIR}/${NET}-join-approved"
PENDING_FILE="${BASE_DIR}/${NET}-join-pending"
DENIED_FILE="${BASE_DIR}/${NET}-join-denied"

_label=$([ -n "$HOST" ] && printf '%s (%s)' "$(_html "$HOST")" "$IP" || printf '%s' "$IP")
QS="net=${NET}&ip=${IP}&mac=${MAC}&host=${HOST}"
_dns=$(nslookup "$IP" 2>/dev/null | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}')
_device_detail="IP: ${IP}
DNS: ${_dns:-unknown}
Hostname: ${HOST:-unknown}
MAC: ${MAC}"

# POST: approve or deny
if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _action=$(_get_param "$_params" action)
    case "$_action" in approve|deny) ;; *) printf '<h1>Invalid action</h1>'; exit 0 ;; esac

    _approver_ip="${REMOTE_ADDR:-unknown}"
    _approver_name=$(_name_for_ip "$_approver_ip")
    _approver_mac=$(_mac_for_ip "$_approver_ip")
    _approver="${_approver_name:-$_approver_ip}"
    [ "$_approver" = "*" ] && _approver="$_approver_ip"
    [ -n "$_approver_mac" ] && _approver="${_approver}, MAC: ${_approver_mac}"

    if [ "$_action" = approve ]; then
        { grep -vF "$MAC" "$APPROVED_FILE" 2>/dev/null; printf '%s\n' "$MAC"; } \
            >"${APPROVED_FILE}.tmp" && mv "${APPROVED_FILE}.tmp" "$APPROVED_FILE" || true
        { grep -v "^${MAC} " "$PENDING_FILE" 2>/dev/null; } \
            >"${PENDING_FILE}.tmp" && mv "${PENDING_FILE}.tmp" "$PENDING_FILE" || true
        { grep -vF "$MAC" "$DENIED_FILE" 2>/dev/null; } \
            >"${DENIED_FILE}.tmp" && mv "${DENIED_FILE}.tmp" "$DENIED_FILE" || true
        nft delete element inet fw4 ${NET}_join_pending "{ $IP }" 2>/dev/null || true
        if [ "${DEVICE_CONTROL:-no}" = yes ]; then
            _ips_f="${BASE_DIR}/${NET}-device-ips"
            _lbl_f="${BASE_DIR}/${NET}-device-labels"
            { grep -v "^${MAC}	" "$_ips_f" 2>/dev/null; printf '%s\t%s\n' "$MAC" "$IP"; } \
                >"${_ips_f}.tmp" && mv "${_ips_f}.tmp" "$_ips_f" || true
            grep -qF "$MAC" "$_lbl_f" 2>/dev/null \
                || printf '%s\t%s\n' "$MAC" "$MAC" >> "$_lbl_f"
            setsid sh /etc/extra-networks/_regen-inspect.sh "$NET" >/dev/null 2>&1 &
        fi
        _ntfy "Access approved — ${NET}" default white_check_mark \
"Type: Internet access approved

Approved device:
${_device_detail}
Approved by: ${_approver}

The approved device can now use the internet on ${NET}."
        _join_history_add "$NET" approved "$MAC" "$IP" "${HOST:-${_dns:-unknown}}" "$_approver" "${JOIN_HISTORY_RETENTION:-90d}"
        _msg="$(_html "${HOST:-$IP}") ($MAC) can now use the internet on ${NET}."
        _cls=ok
    else
        { grep -vF "$MAC" "$DENIED_FILE" 2>/dev/null; printf '%s\n' "$MAC"; } \
            >"${DENIED_FILE}.tmp" && mv "${DENIED_FILE}.tmp" "$DENIED_FILE" || true
        { grep -v "^${MAC} " "$PENDING_FILE" 2>/dev/null; printf '%s %s\n' "$MAC" "$IP"; } \
            >"${PENDING_FILE}.tmp" && mv "${PENDING_FILE}.tmp" "$PENDING_FILE" || true
        nft add element inet fw4 ${NET}_join_pending "{ $IP }" 2>/dev/null || true
        _ntfy "Access denied — ${NET}" default no_entry \
"Type: Internet access denied

Denied device:
${_device_detail}
Denied by: ${_approver}

The denied device remains blocked from internet access on ${NET}."
        _join_history_add "$NET" denied "$MAC" "$IP" "${HOST:-${_dns:-unknown}}" "$_approver" "${JOIN_HISTORY_RETENTION:-90d}"
        _msg="$(_html "${HOST:-$IP}") ($MAC) remains blocked from internet access on ${NET}."
        _cls=err
    fi

    cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$([ "$_cls" = ok ] && echo "Approved" || echo "Kept blocked")</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem}.box{border-radius:8px;padding:1rem;margin:1rem 0}
.ok{background:#e8f5e9}.err{background:#fff8e1}a{color:#1976d2}</style>
</head><body>
<h1>$([ "$_cls" = ok ] && echo "Access approved" || echo "Device kept blocked")</h1>
<div class="box ${_cls}">${_msg}</div>
<p><a href="/cgi-bin/status">Back to dashboard</a></p>
</body></html>
HTML
    exit 0
fi

# GET: show approval form
cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join request — ${NET}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem;margin-bottom:1.5rem}
.card{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}
.label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}
.value{font-weight:600}
button{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;width:100%;margin-top:.5rem}
.btn-ok{background:#1976d2;color:#fff}.btn-ok:active{background:#1565c0}
.btn-deny{background:#c62828;color:#fff}.btn-deny:active{background:#b71c1c}
.note{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}
</style></head><body>
<h1>Join request — ${NET}</h1>
<div class="card">
  <div class="label">Device</div>
  <div class="value">${_label}</div>
</div>
<div class="card">
  <div class="label">MAC address</div>
  <div class="value">${MAC}</div>
</div>
<div class="note">This device joined <strong>${NET}</strong> and is waiting for internet access approval. Approving allows this device; denying keeps it blocked until you approve it later.</div>
<form method="POST" action="/cgi-bin/approve-join?${QS}">
  <input type="hidden" name="action" value="approve">
  <button class="btn-ok" type="submit">Approve internet access</button>
</form>
<form method="POST" action="/cgi-bin/approve-join?${QS}">
  <input type="hidden" name="action" value="deny">
  <button class="btn-deny" type="submit">Deny internet access</button>
</form>
</body></html>
HTML
