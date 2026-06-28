#!/bin/sh
# CGI: approve temporary LAN access to an isolated network device.
# Installed to /www/cgi-bin/approve-access by install.sh when NOTIFY_URL is set.
# Only reachable from LAN — isolated network zones have INPUT=REJECT.

BASE_DIR=/etc/extra-networks
REPO_DIR=$(awk -F= '/^REPO_DIR/ { print $2 }' "${BASE_DIR}/config" 2>/dev/null)
ALLOW_SCRIPT="${REPO_DIR}/tools/allow-service.sh"
. "${BASE_DIR}/_lib.sh"

_get_param() {
    printf '%s' "$1" | tr '&' '\n' | grep "^${2}=" | head -1 | sed "s/^${2}=//"
}

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

_valid_ip() {
    case "$1" in
        *.*.*.*)  printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' ;;
        *:*)      printf '%s' "$1" | grep -qE '^[0-9a-fA-F:]{2,39}$' ;;
        *)        return 1 ;;
    esac
}

_html() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
}

_dur_secs() {
    case "$1" in
        *d) printf '%s' $(( ${1%d} * 86400 )) ;;
        *h) printf '%s' $(( ${1%h} * 3600 )) ;;
        *m) printf '%s' $(( ${1%m} * 60 )) ;;
        *)  printf '0' ;;
    esac
}

# CSRF: reject POSTs whose Origin/Referer is not a private address.
# Browsers omit Origin on same-origin navigations, so a missing header is allowed.
if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _origin="${HTTP_ORIGIN:-${HTTP_REFERER:-}}"
    case "$_origin" in
        ""|http://192.168.*|http://10.*|http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) ;;
        http://\[fd*|http://\[fc*|http://\[fe80*|http://\[::1\]*) ;;  # IPv6 ULA / link-local
        *) printf 'Content-Type: text/html\r\n\r\nForbidden'; exit 0 ;;
    esac
fi

# Read parameters from GET query string or POST body
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ -n "${CONTENT_LENGTH:-}" ]; then
    # Bound CONTENT_LENGTH to prevent hanging on oversized bodies
    printf '%s' "$CONTENT_LENGTH" | grep -qE '^[0-9]+$' && [ "$CONTENT_LENGTH" -le 4096 ] \
        || { printf 'Content-Type: text/html\r\n\r\nBad request'; exit 0; }
    _params=$(head -c "$CONTENT_LENGTH")
    # Carry GET params too — duration/reason come from POST, the rest from GET query string
    [ -n "$QUERY_STRING" ] && _params="${QUERY_STRING}&${_params}"
else
    _params="$QUERY_STRING"
fi

NET=$(_get_param "$_params" net)
SRC=$(_get_param "$_params" src)
DST=$(_get_param "$_params" dst)
PROTO=$(_get_param "$_params" proto)
PORT=$(_get_param "$_params" port)
DURATION=$(_get_param "$_params" duration)
REASON=$(_urldecode "$(_get_param "$_params" reason)")

printf 'Content-Type: text/html\r\n\r\n'

# ── input validation ──────────────────────────────────────────────────────────

_valid_ip "$SRC" && _valid_ip "$DST" \
    || { printf '<h1>Invalid IP</h1>'; exit 0; }
printf '%s' "$PORT" | grep -qE '^[0-9]+$' \
    && [ "$PORT" -ge 1 ] 2>/dev/null && [ "$PORT" -le 65535 ] 2>/dev/null \
    || { printf '<h1>Invalid port</h1>'; exit 0; }
[ "$PROTO" = tcp ] || [ "$PROTO" = udp ] \
    || { printf '<h1>Invalid protocol</h1>'; exit 0; }
printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' \
    || { printf '<h1>Invalid network</h1>'; exit 0; }
uci -q get firewall."${NET}_zone" >/dev/null 2>&1 \
    || { printf '<h1>Unknown network: %s</h1>' "$NET"; exit 0; }

# ── load per-network notify config ────────────────────────────────────────────

NOTIFY_URL=""
DEFAULT_DURATION="24h"
MAX_DURATION="30d"
REASON_REQUIRED="no"
[ -f "${BASE_DIR}/${NET}-notify.conf" ] && . "${BASE_DIR}/${NET}-notify.conf"
_max_secs=$(_dur_secs "$MAX_DURATION")

# ── resolve names and MACs ────────────────────────────────────────────────────

src_name=$(_name_for_ip "$SRC")
dst_name=$(_name_for_ip "$DST")
src_mac=$(_mac_for_ip  "$SRC")
dst_mac=$(_mac_for_ip  "$DST")
src_label=$([ -n "$src_name" ] && printf '%s (%s)' "$(_html "$src_name")" "$SRC" || printf '%s' "$SRC")
dst_label=$([ -n "$dst_name" ] && printf '%s (%s)' "$(_html "$dst_name")" "$DST" || printf '%s' "$DST")
src_plain=$([ -n "$src_name" ] && printf '%s (%s)' "$src_name" "$SRC" || printf '%s' "$SRC")
dst_plain=$([ -n "$dst_name" ] && printf '%s (%s)' "$dst_name" "$DST" || printf '%s' "$DST")

QS="net=${NET}&src=${SRC}&dst=${DST}&proto=${PROTO}&port=${PORT}"

# ── POST: execute and confirm ─────────────────────────────────────────────────

if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    case "${DURATION:-}" in
        1h|6h|12h|24h|2d|7d|30d) ;;
        *) printf '<h1>Invalid duration</h1>'; exit 0 ;;
    esac

    if [ "$(_dur_secs "$DURATION")" -gt "$_max_secs" ]; then
        printf '<h1>Duration exceeds maximum (%s)</h1>' "$(_html "$MAX_DURATION")"; exit 0
    fi

    if [ "$REASON_REQUIRED" = yes ] && [ -z "$REASON" ]; then
        cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reason required</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem}
.box{border-radius:8px;padding:.75rem 1rem;margin:1rem 0;background:#fff8e1;font-size:.9rem}
a{color:#1976d2}
</style></head><body>
<h1>Reason required</h1>
<div class="box">Please go back and enter a reason for this approval.</div>
<p><a href="/cgi-bin/approve-access?${QS}">Back</a></p>
</body></html>
HTML
        exit 0
    fi

    _dest_zone=""
    [ "$(_get_param "$_params" dest_zone)" = lan ] && _dest_zone=lan
    result=$("$ALLOW_SCRIPT" "$NET" "$DST" "$PROTO" "$PORT" "$DURATION" ${_dest_zone:+lan} 2>&1)
    ok=$?

    if [ "$ok" -eq 0 ]; then
        _ntfy "Approved — ${NET}" default white_check_mark \
"Type: Access approved

From: ${src_plain}${src_mac:+ [${src_mac}]}
To:   ${dst_plain}${dst_mac:+ [${dst_mac}]}:${PORT}/${PROTO}
Duration: ${DURATION}${REASON:+
Reason: ${REASON}}"
    fi

    cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$([ "$ok" -eq 0 ] && echo "Access granted" || echo "Error")</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem}
.box{border-radius:8px;padding:1rem;margin:1rem 0;white-space:pre-wrap;font-family:monospace;font-size:.9rem}
.ok{background:#e8f5e9} .err{background:#ffebee}
a{color:#1976d2}
</style></head><body>
HTML

    if [ "$ok" -eq 0 ]; then
        printf '<h1>Access granted</h1>\n'
        printf '<div class="box ok">%s</div>\n' "$(_html "$result")"
    else
        printf '<h1>Error</h1>\n'
        printf '<div class="box err">%s</div>\n' "$(_html "$result")"
    fi
    printf '<p><a href="/cgi-bin/approve-access?%s">Back</a></p>\n' "$QS"
    printf '</body></html>\n'
    exit 0
fi

# ── GET: show approval form ───────────────────────────────────────────────────

_dur_option() {
    # emit <option> only if the duration does not exceed MAX_DURATION
    [ "$(_dur_secs "$1")" -le "$_max_secs" ] || return 0
    [ "$1" = "$DEFAULT_DURATION" ] \
        && printf '<option value="%s" selected>%s</option>\n' "$1" "$2" \
        || printf '<option value="%s">%s</option>\n' "$1" "$2"
}

_required_note=$([ "$REASON_REQUIRED" = yes ] \
    && printf ' <span style="color:#c62828">*</span>' || true)
_required_attr=$([ "$REASON_REQUIRED" = yes ] && printf ' required' || true)

cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve access — ${NET}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem;margin-bottom:1.5rem}
.card{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}
.label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}
.value{font-weight:600}
select,textarea{font-size:1rem;padding:.5rem .75rem;border-radius:6px;border:1px solid #ccc;
       display:block;width:100%;margin:.5rem 0;box-sizing:border-box}
textarea{resize:vertical;min-height:4rem}
button{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;
       background:#1976d2;color:#fff;width:100%;margin-top:.5rem}
button:active{background:#1565c0}
.note{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}
</style></head><body>
<h1>Access request — ${NET}</h1>

<div class="card">
  <div class="label">From (LAN)</div>
  <div class="value">${src_label}</div>
</div>
<div class="card">
  <div class="label">To (${NET})</div>
  <div class="value">${dst_label}:${PORT}/${PROTO}</div>
</div>

<div class="note">This page is only accessible from your home LAN.</div>

<form method="POST" action="/cgi-bin/approve-access?${QS}">
  <div class="label" style="margin-top:1.25rem">Allow for</div>
  <select name="duration">
HTML

_dur_option 1h  "1 hour"
_dur_option 6h  "6 hours"
_dur_option 12h "12 hours"
_dur_option 24h "24 hours"
_dur_option 2d  "2 days"
_dur_option 7d  "1 week"
_dur_option 30d "30 days"

cat <<HTML
  </select>
  <div class="label" style="margin-top:1.25rem">Reason${_required_note}</div>
  <textarea name="reason" placeholder="Why is this access needed?"${_required_attr}></textarea>
  <button type="submit">Allow access</button>
</form>
</body></html>
HTML
