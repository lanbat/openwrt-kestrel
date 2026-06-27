#!/bin/sh
# CGI: approve temporary LAN access to an isolated network device.
# Installed to /www/cgi-bin/approve-access by install.sh when NOTIFY_URL is set.
# Only reachable from LAN — isolated network zones have INPUT=REJECT.

BASE_DIR=/etc/extra-networks
REPO_DIR=$(awk -F= '/^REPO_DIR/ { print $2 }' "${BASE_DIR}/config" 2>/dev/null)
ALLOW_SCRIPT="${REPO_DIR}/tools/allow-service.sh"

_get_param() {
    printf '%s' "$1" | tr '&' '\n' | grep "^${2}=" | head -1 | sed "s/^${2}=//"
}

_valid_ip() {
    echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

# Read parameters from GET query string or POST body
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ -n "${CONTENT_LENGTH:-}" ]; then
    _params=$(head -c "$CONTENT_LENGTH")
    # Also carry GET params for hidden fields on GET→POST form
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

# ── resolve names ─────────────────────────────────────────────────────────────

src_name=$(awk -v ip="$SRC" '$3==ip { print $4; exit }' /tmp/dhcp.leases 2>/dev/null)
dst_name=$(awk -v ip="$DST" '$3==ip { print $4; exit }' /tmp/dhcp.leases 2>/dev/null)
src_label=$([ -n "$src_name" ] && printf '%s (%s)' "$src_name" "$SRC" || printf '%s' "$SRC")
dst_label=$([ -n "$dst_name" ] && printf '%s (%s)' "$dst_name" "$DST" || printf '%s' "$DST")

QS="net=${NET}&src=${SRC}&dst=${DST}&proto=${PROTO}&port=${PORT}"

# ── POST: execute and confirm ─────────────────────────────────────────────────

if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ -n "$DURATION" ]; then
    case "$DURATION" in
        1h|6h|12h|24h|2d|7d|30d) ;;
        *) printf '<h1>Invalid duration</h1>'; exit 0 ;;
    esac

    result=$("$ALLOW_SCRIPT" "$NET" "$DST" "$PROTO" "$PORT" "$DURATION" 2>&1)
    ok=$?

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
        printf '<div class="box ok">%s</div>\n' "$result"
    else
        printf '<h1>Error</h1>\n'
        printf '<div class="box err">%s</div>\n' "$result"
    fi
    printf '<p><a href="/cgi-bin/approve-access?%s">Back</a></p>\n' "$QS"
    printf '</body></html>\n'
    exit 0
fi

# ── GET: show approval form ───────────────────────────────────────────────────

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
select{font-size:1rem;padding:.5rem .75rem;border-radius:6px;border:1px solid #ccc;
       display:block;width:100%;margin:.5rem 0;box-sizing:border-box}
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
    <option value="1h">1 hour</option>
    <option value="6h">6 hours</option>
    <option value="12h">12 hours</option>
    <option value="24h" selected>24 hours</option>
    <option value="2d">2 days</option>
    <option value="7d">1 week</option>
    <option value="30d">30 days</option>
  </select>
  <button type="submit">Allow access</button>
</form>
</body></html>
HTML
