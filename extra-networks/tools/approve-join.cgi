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
printf '%s' "$MAC" | grep -qiE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
    || { printf '<h1>Invalid MAC</h1>'; exit 0; }

_load_notify "$NET"
_iface="${IFACE_NAME:-$NET}"

# Handle set_label before IP validation — saving a label doesn't require an IP
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ "$(_get_param "$_params" action)" = set_label ]; then
    _new=$(printf '%s' "$(_get_param "$_params" label)" \
        | sed 's/+/ /g;s/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 40)
    if [ -n "$_new" ]; then
        _lbl_f="${BASE_DIR}/${NET}-device-labels"
        _old_label=$(awk -v m="$MAC" \
            'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
            "$_lbl_f" 2>/dev/null || true)
        { grep -v "^${MAC}	" "$_lbl_f" 2>/dev/null
          printf '%s\t%s\n' "$MAC" "$_new"; } > "${_lbl_f}.tmp" \
            && mv "${_lbl_f}.tmp" "$_lbl_f" || true
        _slug=$(_slugify "$_new")
        _write_device_dns "$_iface" "$MAC" "$_slug" \
            "$(_ip4_for_mac "$MAC")" "$(_ip6_for_mac "$MAC")"
        _actor_ip="${REMOTE_ADDR:-unknown}"
        _actor_name=$(_name_for_ip "$_actor_ip")
        _actor_mac=$(_mac_for_ip "$_actor_ip")
        case "$_actor_ip" in
            *:*) _actor_ip6="$_actor_ip"; _actor_ip4=$([ -n "$_actor_mac" ] && _ip4_for_mac "$_actor_mac" || true) ;;
            *)   _actor_ip4="$_actor_ip"; _actor_ip6=$([ -n "$_actor_mac" ] && _ip6_for_mac "$_actor_mac" || true) ;;
        esac
        [ "$_actor_name" = "*" ] && _actor_name=""
        _actor_display="${_actor_name:-${_actor_ip4:-$_actor_ip}}"
        if [ "$_new" != "$_old_label" ]; then
            _ntfy "Label set — ${_iface}" default pencil2 \
                "MAC: ${MAC}${_old_label:+
Was: ${_old_label}}
Now: ${_new}

By: ${_actor_display}${_actor_mac:+ (${_actor_mac})}
IPv4: ${_actor_ip4:----}
IPv6: ${_actor_ip6:----}"
            _join_history_add "$_iface" labelled "$MAC" \
                "$(_ip4_for_mac "$MAC")" "$(_ip6_for_mac "$MAC")" \
                "${_old_label:+${_old_label} → }${_new}" \
                "$_actor_display" "$_actor_ip4" "$_actor_ip6" "$_actor_mac" \
                "${JOIN_HISTORY_RETENTION:-90d}"
        fi
    fi
    printf '<meta http-equiv="refresh" content="0;url=/cgi-bin/status">'
    exit 0
fi

# Handle allowlist_add — add a WiFi-associated device to the MAC allowlist
if [ "${REQUEST_METHOD:-GET}" = "POST" ] && [ "$(_get_param "$_params" action)" = allowlist_add ]; then
    [ "${ALLOWLIST:-no}" = yes ] \
        || { printf '<h1>Network %s does not use an allowlist</h1>' "$(_html "$NET")"; exit 0; }
    _label_new=$(printf '%s' "$(_get_param "$_params" label)" \
        | sed 's/+/ /g;s/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 40)
    [ -n "$_label_new" ] || { printf '<h1>Label is required</h1>'; exit 0; }
    _ip_new=$(_urldecode "$(_get_param "$_params" ip)")
    _valid_ip "$_ip_new" || { printf '<h1>Invalid IP</h1>'; exit 0; }
    case "$_ip_new" in "${SUBNET}."*) ;; \
        *) printf '<h1>IP must be in subnet %s.0/24</h1>' "$(_html "${SUBNET:-?}")"; exit 0 ;; esac

    _allowed_macs_f="${BASE_DIR}/${NET}-allowed-macs"
    { grep -vi "^${MAC}[[:space:]]" "$_allowed_macs_f" 2>/dev/null
      printf '%s\t%s\t%s\n' "$MAC" "$_ip_new" "$_label_new"; } \
        > "${_allowed_macs_f}.tmp" && mv "${_allowed_macs_f}.tmp" "$_allowed_macs_f" || true

    _lbl_f="${BASE_DIR}/${NET}-device-labels"
    { grep -v "^${MAC}	" "$_lbl_f" 2>/dev/null
      printf '%s\t%s\n' "$MAC" "$_label_new"; } > "${_lbl_f}.tmp" \
        && mv "${_lbl_f}.tmp" "$_lbl_f" || true

    ACTION=ifup INTERFACE="$_iface" sh "/etc/hotplug.d/iface/51-${_iface}-macfilter" \
        >/dev/null 2>&1 || true

    _ntfy "Device added — ${_iface}" default white_check_mark \
"${MAC} added to ${_iface} allowlist.
Label: ${_label_new}
IP: ${_ip_new}"

    _redirect=$(_urldecode "$(_get_param "$_params" redirect)")
    case "$_redirect" in /cgi-bin/*) ;; *) _redirect="/cgi-bin/status" ;; esac
    printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_redirect")"
    exit 0
fi

_valid_ip "$IP" || { printf '<h1>Invalid IP</h1>'; exit 0; }

APPROVED_FILE="${BASE_DIR}/${NET}-join-approved"
PENDING_FILE="${BASE_DIR}/${NET}-join-pending"
DENIED_FILE="${BASE_DIR}/${NET}-join-denied"
IP6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
    | awk -v m="$MAC" '!/^fe80:/ && /lladdr/ { for(i=1;i<=NF;i++) if($i=="lladdr" && tolower($(i+1))==tolower(m)){print $1; exit} }')
case "$IP" in
    *:*) IP6="$IP"; IP4=$(_ip4_for_mac "$MAC"); _pending_set="${NET}_join_pending6"; _ip_store="${BASE_DIR}/${NET}-device-ip6s" ;;
    *)   IP4="$IP"; _pending_set="${NET}_join_pending";  _ip_store="${BASE_DIR}/${NET}-device-ips" ;;
esac

_label=$([ -n "$HOST" ] && printf '%s (%s)' "$(_html "$HOST")" "$IP" || printf '%s' "$IP")
QS="net=${NET}&ip=${IP}&mac=${MAC}&host=${HOST}"
_dns=$(nslookup "$IP" 2>/dev/null | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}')
_device_detail="IP: ${IP}
IPv6: ${IP6:-unknown}
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
    case "$_approver_ip" in
        *:*) _approver_ip6="$_approver_ip"; _approver_ip4=$([ -n "$_approver_mac" ] && _ip4_for_mac "$_approver_mac" || true) ;;
        *)   _approver_ip4="$_approver_ip"; _approver_ip6=$([ -n "$_approver_mac" ] && _ip6_for_mac "$_approver_mac" || true) ;;
    esac
    _approver="${_approver_name:-$_approver_ip}"
    [ "$_approver" = "*" ] && _approver="$_approver_ip"
    [ -n "$_approver_mac" ] && _approver="${_approver} (${_approver_mac})"
    _rip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
    _rip="${_rip:-192.168.1.1}"
    _approver_action=""
    [ -n "$_approver_mac" ] && _approver_action="view, Approver, http://${_rip}/cgi-bin/device?net=lan&mac=${_approver_mac}"

    if [ "$_action" = approve ]; then
        _label_new=$(printf '%s' "$(_get_param "$_params" label)" \
            | sed 's/+/ /g;s/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 40)
        if [ -z "$_label_new" ]; then
            _label_new=$(awk -v m="$MAC" \
                'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
                "${BASE_DIR}/${NET}-device-labels" 2>/dev/null || true)
        fi
        [ -n "$_label_new" ] || { printf '<h1>Label is required to approve a device</h1>'; exit 0; }
        { grep -vF "$MAC" "$APPROVED_FILE" 2>/dev/null; printf '%s\n' "$MAC"; } \
            >"${APPROVED_FILE}.tmp" && mv "${APPROVED_FILE}.tmp" "$APPROVED_FILE" || true
        { grep -v "^${MAC} " "$PENDING_FILE" 2>/dev/null; } \
            >"${PENDING_FILE}.tmp" && mv "${PENDING_FILE}.tmp" "$PENDING_FILE" || true
        { grep -vF "$MAC" "$DENIED_FILE" 2>/dev/null; } \
            >"${DENIED_FILE}.tmp" && mv "${DENIED_FILE}.tmp" "$DENIED_FILE" || true
        nft delete element inet fw4 "$_pending_set" "{ $IP }" 2>/dev/null || true
        [ -n "$IP6" ] && nft delete element inet fw4 "${NET}_join_pending6" "{ $IP6 }" 2>/dev/null || true
        case "$IP" in
            *:*) nft add element inet fw4 "${NET}_join_approved_ips6" "{ $IP }" 2>/dev/null || true ;;
            *)   nft add element inet fw4 "${NET}_join_approved_ips"  "{ $IP }" 2>/dev/null || true ;;
        esac
        [ -n "$IP6" ] && nft add element inet fw4 "${NET}_join_approved_ips6" "{ $IP6 }" 2>/dev/null || true
        _approved_ips_f="${BASE_DIR}/${NET}-join-approved-ips"
        { grep -v "^${MAC} " "$_approved_ips_f" 2>/dev/null
          printf '%s %s\n' "$MAC" "${IP4:-$IP}"; } >"${_approved_ips_f}.tmp" \
            && mv "${_approved_ips_f}.tmp" "$_approved_ips_f" || true
        if [ "${DEVICE_CONTROL:-no}" = yes ]; then
            _lbl_f="${BASE_DIR}/${NET}-device-labels"
            { grep -v "^${MAC}	" "$_ip_store" 2>/dev/null; printf '%s\t%s\n' "$MAC" "$IP"; } \
                >"${_ip_store}.tmp" && mv "${_ip_store}.tmp" "$_ip_store" || true
            if [ -n "$IP6" ]; then
                _ip6_store="${BASE_DIR}/${NET}-device-ip6s"
                { grep -v "^${MAC}	" "$_ip6_store" 2>/dev/null; printf '%s\t%s\n' "$MAC" "$IP6"; } \
                    >"${_ip6_store}.tmp" && mv "${_ip6_store}.tmp" "$_ip6_store" || true
            fi
            setsid sh /etc/extra-networks/_regen-inspect.sh "$NET" >/dev/null 2>&1 &
        fi
        _lbl_f="${BASE_DIR}/${NET}-device-labels"
        { grep -v "^${MAC}	" "$_lbl_f" 2>/dev/null
          printf '%s\t%s\n' "$MAC" "$_label_new"; } > "${_lbl_f}.tmp" \
            && mv "${_lbl_f}.tmp" "$_lbl_f" || true
        _slug=$(_slugify "$_label_new")
        _write_device_dns "$_iface" "$MAC" "$_slug" \
            "${IP4:-$IP}" "$(_ip6_for_mac "$MAC")"
        _ntfy "Access approved — ${NET}" default white_check_mark \
"Type: Internet access approved

Approved device:
${_device_detail}

By: ${_approver}
IPv4: ${_approver_ip4:----}
IPv6: ${_approver_ip6:----}

The approved device can now use the internet on ${NET}." \
"${_approver_action}"
        _join_history_add "$NET" approved "$MAC" "$IP4" "$IP6" "${HOST:-${_dns:-unknown}}" "$_approver" "$_approver_ip4" "$_approver_ip6" "$_approver_mac" "${JOIN_HISTORY_RETENTION:-90d}"
        _msg="$(_html "${HOST:-$IP}") ($MAC) can now use the internet on ${NET}."
        _cls=ok
    else
        { grep -vF "$MAC" "$DENIED_FILE" 2>/dev/null; printf '%s\n' "$MAC"; } \
            >"${DENIED_FILE}.tmp" && mv "${DENIED_FILE}.tmp" "$DENIED_FILE" || true
        { grep -v "^${MAC} " "$PENDING_FILE" 2>/dev/null
          printf '%s %s\n' "$MAC" "$IP"
          [ -n "$IP6" ] && printf '%s %s\n' "$MAC" "$IP6"; } \
            >"${PENDING_FILE}.tmp" && mv "${PENDING_FILE}.tmp" "$PENDING_FILE" || true
        nft add element inet fw4 "$_pending_set" "{ $IP }" 2>/dev/null || true
        [ -n "$IP6" ] && nft add element inet fw4 "${NET}_join_pending6" "{ $IP6 }" 2>/dev/null || true
        _ntfy "Access denied — ${NET}" default no_entry \
"Type: Internet access denied

Denied device:
${_device_detail}

By: ${_approver}
IPv4: ${_approver_ip4:----}
IPv6: ${_approver_ip6:----}

The denied device remains blocked from internet access on ${NET}." \
"${_approver_action}"
        _join_history_add "$NET" denied "$MAC" "$IP4" "$IP6" "${HOST:-${_dns:-unknown}}" "$_approver" "$_approver_ip4" "$_approver_ip6" "$_approver_mac" "${JOIN_HISTORY_RETENTION:-90d}"
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
_existing_label=$(awk -v m="$MAC" \
    'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' \
    "${BASE_DIR}/${NET}-device-labels" 2>/dev/null || true)
cat <<HTML
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join request — ${NET}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:1rem;color:#111}
h1{font-size:1.3rem;margin-bottom:1.5rem}
.card{background:#f5f5f5;border-radius:8px;padding:1rem;margin:.75rem 0}
.lbl{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#888;margin-bottom:.25rem}
.value{font-weight:600}
input[type=text]{width:100%;box-sizing:border-box;padding:.5rem .75rem;font-size:1rem;border:1px solid #ccc;border-radius:6px;margin-top:.25rem}
button{font-size:1rem;padding:.65rem 1rem;border-radius:6px;border:none;cursor:pointer;width:100%;margin-top:.5rem}
.btn-ok{background:#1976d2;color:#fff}.btn-ok:active{background:#1565c0}
.btn-deny{background:#c62828;color:#fff}.btn-deny:active{background:#b71c1c}
.note{background:#fff8e1;border-radius:8px;padding:.75rem;font-size:.85rem;margin:1rem 0}
</style></head><body>
<h1>Join request — ${NET}</h1>
<div class="card">
  <div class="lbl">Device</div>
  <div class="value">${_label}</div>
</div>
<div class="card">
  <div class="lbl">MAC address</div>
  <div class="value">${MAC}</div>
</div>
<div class="note">This device joined <strong>${NET}</strong> and is waiting for internet access approval. Give it a label, then approve or deny.</div>
<form method="POST" action="/cgi-bin/approve-join?${QS}">
  <input type="hidden" name="action" value="approve">
  <div class="lbl" style="margin-top:1rem">Label <span style="color:#c62828">*</span></div>
  <input type="text" name="label" value="$(_html "$_existing_label")" placeholder="e.g. Alice's Phone" required maxlength="40">
  <button class="btn-ok" type="submit">Approve internet access</button>
</form>
<form method="POST" action="/cgi-bin/approve-join?${QS}">
  <input type="hidden" name="action" value="deny">
  <button class="btn-deny" type="submit">Deny internet access</button>
</form>
</body></html>
HTML
