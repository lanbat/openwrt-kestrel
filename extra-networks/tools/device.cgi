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
_rel_time() {
    _rt_diff=$(( $(date +%s) - ${1:-0} ))
    if   [ "$_rt_diff" -lt 60 ];    then printf 'just now'
    elif [ "$_rt_diff" -lt 3600 ];  then printf '%d min ago' $(( _rt_diff / 60 ))
    elif [ "$_rt_diff" -lt 86400 ]; then printf '%dh ago'    $(( _rt_diff / 3600 ))
    else                                  printf '%dd ago'   $(( _rt_diff / 86400 ))
    fi
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
    printf '%s' "$CONTENT_LENGTH" | grep -qE '^[0-9]+$' && [ "$CONTENT_LENGTH" -le 16384 ] \
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
_ip6s_f="${BASE_DIR}/${_iface}-device-ip6s"
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
[ -n "$_DEV_IP" ] || _DEV_IP=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' \
    "${BASE_DIR}/${_iface}-join-approved-ips" 2>/dev/null || true)
[ -n "$_DEV_IP" ] || _DEV_IP=$(_ip4_for_mac "$MAC")
[ -n "$_DEV_IP" ] || _DEV_IP=$(awk -F'\t' -v m="$MAC" \
    'tolower($4)==tolower(m)&&$5~/^[0-9]+\.[0-9]/{ip=$5}END{print ip}' \
    "${BASE_DIR}/${_iface}-join-history" 2>/dev/null)
_DEV_IP6=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' \
    "$_ip6s_f" 2>/dev/null || true)
[ -n "$_DEV_IP6" ] || _DEV_IP6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
    | awk -v m="$MAC" '!/^fe80:/ && /lladdr/ { for(i=1;i<=NF;i++) if($i=="lladdr" && tolower($(i+1))==tolower(m)){print $1; exit} }')
_DEV_LIMIT=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' \
    "$_limits_f" 2>/dev/null || true)
_DEV_LIMIT="${_DEV_LIMIT:-120}"
_DEV_SLUG=$(_slugify "${_DEV_LABEL:-}")
_LOCAL_DOMAIN=$(uci -q get dhcp.@dnsmasq[0].domain 2>/dev/null || true)
_LOCAL_DOMAIN="${_LOCAL_DOMAIN:-lan}"
_DEV_FQDN="${_DEV_SLUG:+${_DEV_SLUG}.${_LOCAL_DOMAIN}}"
_DEV_HN=$(awk -v m="$MAC" 'tolower($2)==tolower(m)&&$4!="*"{print $4;exit}' /tmp/dhcp.leases 2>/dev/null || true)
if [ -z "$_DEV_HN" ]; then
    _uci_idx=$(uci show dhcp 2>/dev/null | grep -i "'${MAC}'" | grep -oE "@host\[[0-9]+\]" | head -1)
    [ -n "$_uci_idx" ] && _DEV_HN=$(uci -q get "dhcp.${_uci_idx}.name" 2>/dev/null || true)
fi
if [ -n "$_DEV_LABEL" ]; then
    _DEV_DISPLAY="$_DEV_LABEL"
elif [ -n "$_DEV_HN" ]; then
    _DEV_DISPLAY="${_DEV_HN} (unlabelled)"
else
    _DEV_DISPLAY="${MAC} (unlabelled)"
fi
_DEV_DNS_DISPLAY="${_DEV_FQDN:----}"
_DEV_HN_FQDN="${_DEV_HN:+${_DEV_HN}.${_LOCAL_DOMAIN}}"
[ -z "$_DEV_FQDN" ] && _DEV_DNS_DISPLAY="${_DEV_HN_FQDN:----}"
[ -n "$_DEV_FQDN" ] && [ -n "$_DEV_HN_FQDN" ] && [ "$_DEV_HN_FQDN" != "$_DEV_FQDN" ] && \
    _DEV_DNS_DISPLAY="${_DEV_FQDN}<br><span class=\"dim\">${_DEV_HN_FQDN}</span>"
_BACK_URL="/cgi-bin/device?net=${NET}&mac=${MAC}"
_rip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
_rip="${_rip:-192.168.1.1}"
_DEV_URL="http://${_rip}${_BACK_URL}"
_split_dir="/etc/split-routing"
_vpn_list=$(
    for _vf in "${_split_dir}"/vpn-*.conf; do
        [ -f "$_vf" ] || continue
        _vn="${_vf##*/vpn-}"; _vn="${_vn%.conf}"
        _vpi=$(awk -F= '/^VPN_IFACE/{gsub(/[" \t]/, "", $2); print $2; exit}' "$_vf" 2>/dev/null)
        _vpfm=$(awk -F= '/^FWMARK/{gsub(/[" \t]/, "", $2); print $2; exit}' "$_vf" 2>/dev/null)
        [ -n "$_vpi" ] && [ -n "$_vpfm" ] \
            && printf '%s\t%s\t%s\n' "$_vn" "$_vpi" "$_vpfm"
    done
)
_vpn_options=$(printf '%s\n' "$_vpn_list" | while IFS=$(printf '\t') read -r _vn _vi _vfm; do
    [ -z "$_vn" ] && continue
    _vlbl=$(printf '%s' "$_vn" | awk '{print toupper($0)}')
    printf '<option value="%s">%s (%s)</option>\n' "$(_html "$_vn")" "$(_html "$_vlbl")" "$(_html "$_vi")"
done)
_JOIN_IP="${_DEV_IP:-$_DEV_IP6}"
_JOIN_STATE=Untracked
grep -qixF "$MAC" "$_join_approved_f" 2>/dev/null && _JOIN_STATE=Approved
grep -qixF "$MAC" "$_join_denied_f" 2>/dev/null && _JOIN_STATE=Denied
grep -qi "^${MAC} " "$_join_pending_f" 2>/dev/null && [ "$_JOIN_STATE" = Untracked ] && _JOIN_STATE=Pending

# ── POST actions ──────────────────────────────────────────────────────────────

if [ "${REQUEST_METHOD:-GET}" = "POST" ]; then
    _action=$(_get_param "$_params" action)
    printf 'Content-Type: text/html\r\n\r\n'

    # Resolve actor (browser client making the request) — shared across all actions
    _actor_ip="${REMOTE_ADDR:-unknown}"
    _actor_name=$(_name_for_ip "$_actor_ip")
    _actor_mac=$(_mac_for_ip "$_actor_ip")
    case "$_actor_ip" in
        *:*) _actor_ip6="$_actor_ip"; _actor_ip4=$([ -n "$_actor_mac" ] && _ip4_for_mac "$_actor_mac" || true) ;;
        *)   _actor_ip4="$_actor_ip"; _actor_ip6=$([ -n "$_actor_mac" ] && _ip6_for_mac "$_actor_mac" || true) ;;
    esac
    [ "$_actor_name" = "*" ] && _actor_name=""
    _actor_display="${_actor_name:-${_actor_ip4:-$_actor_ip}}"
    _actor_info="By: ${_actor_display}${_actor_mac:+ (${_actor_mac})}
IPv4: ${_actor_ip4:----}
IPv6: ${_actor_ip6:----}"

    case "$_action" in

    set_label)
        _new=$(printf '%s' "$(_get_param "$_params" label)" \
            | sed 's/+/ /g;s/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 40)
        if [ -n "$_new" ]; then
            mkdir -p "$BASE_DIR"
            _upsert "$_labels_f" "$MAC" "$_new"
            _slug=$(_slugify "$_new")
            _write_device_dns "$_iface" "$MAC" "$_slug" \
                "${_DEV_IP:-$(_ip4_for_mac "$MAC")}" "${_DEV_IP6:-$(_ip6_for_mac "$MAC")}"
            if [ "$_new" != "$_DEV_LABEL" ]; then
                _ntfy "Label set — ${_iface}" default pencil2 \
                    "MAC: ${MAC}${_DEV_LABEL:+
Was: ${_DEV_LABEL}}
Now: ${_new}

${_actor_info}" \
                    "view, Device, ${_DEV_URL}"
                _join_history_add "$_iface" labelled "$MAC" \
                    "${_DEV_IP:-$(_ip4_for_mac "$MAC")}" "${_DEV_IP6:-$(_ip6_for_mac "$MAC")}" \
                    "${_DEV_LABEL:+${_DEV_LABEL} → }${_new}" \
                    "$_actor_display" "$_actor_ip4" "$_actor_ip6" "$_actor_mac" \
                    "${JOIN_HISTORY_RETENTION:-90d}"
            fi
        fi
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
        _approver_action=""
        [ -n "$_actor_mac" ] && _approver_action="view, Approver, http://${_rip}/cgi-bin/device?net=lan&mac=${_actor_mac}"
        _notify_ip="${_DEV_IP:-${_DEV_IP6:-}}"
        _dns=$([ -n "$_notify_ip" ] && nslookup "$_notify_ip" 2>/dev/null | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}' || true)
        _device_detail="IPv4: ${_DEV_IP:-unknown}
IPv6: ${_DEV_IP6:-unknown}
DNS: ${_dns:-unknown}
Hostname: ${_DEV_LABEL:-unknown}
MAC: ${MAC}"
        [ -f "$_join_approved_f" ] && {
            grep -vixF "$MAC" "$_join_approved_f" > "${_join_approved_f}.tmp" 2>/dev/null \
                && mv "${_join_approved_f}.tmp" "$_join_approved_f" || true
        }
        { grep -vi "^${MAC} " "$_join_pending_f" 2>/dev/null
          [ -n "$_DEV_IP" ] && printf '%s %s\n' "$MAC" "$_DEV_IP"
          [ -n "$_DEV_IP6" ] && printf '%s %s\n' "$MAC" "$_DEV_IP6"; } \
            > "${_join_pending_f}.tmp" && mv "${_join_pending_f}.tmp" "$_join_pending_f" || true
        [ -n "$_DEV_IP" ]  && nft delete element inet fw4 "${_iface}_join_approved_ips"  "{ ${_DEV_IP} }"  2>/dev/null || true
        [ -n "$_DEV_IP6" ] && nft delete element inet fw4 "${_iface}_join_approved_ips6" "{ ${_DEV_IP6} }" 2>/dev/null || true
        [ -n "$_DEV_IP" ]  && nft add element inet fw4 "${_iface}_join_pending"  "{ ${_DEV_IP} }"  2>/dev/null || true
        [ -n "$_DEV_IP6" ] && nft add element inet fw4 "${_iface}_join_pending6" "{ ${_DEV_IP6} }" 2>/dev/null || true
        _approved_ips_f="${BASE_DIR}/${_iface}-join-approved-ips"
        grep -v "^${MAC} " "$_approved_ips_f" > "${_approved_ips_f}.tmp" 2>/dev/null \
            && mv "${_approved_ips_f}.tmp" "$_approved_ips_f" || true
        { grep -vixF "$MAC" "$_join_denied_f" 2>/dev/null; } \
            > "${_join_denied_f}.tmp" && mv "${_join_denied_f}.tmp" "$_join_denied_f" || true
        _join_history_add "$_iface" revoked "$MAC" "$_DEV_IP" "$_DEV_IP6" "${_DEV_LABEL:-${_dns:-unknown}}" "$_actor_display" "$_actor_ip4" "$_actor_ip6" "$_actor_mac" "${JOIN_HISTORY_RETENTION:-90d}"
        _ntfy "Access revoked — ${_iface}" default no_entry \
"Type: Internet access revoked

Revoked device:
${_device_detail}

${_actor_info}

The device is no longer approved on ${_iface}." \
"view, Device, ${_DEV_URL}${_approver_action:+; ${_approver_action}}"
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    approve_domain)
        _dom=$(printf '%s' "$(_get_param "$_params" domain)" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
            | awk '{print tolower($0)}')
        printf '%s' "$_dom" | grep -qE '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' \
            || { printf '<h1>Invalid domain</h1>'; exit 0; }
        _route=$(printf '%s' "$(_get_param "$_params" route)" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        _route_fwmark=""
        if [ -n "$_route" ]; then
            _vpf="${_split_dir}/vpn-${_route}.conf"
            [ -f "$_vpf" ] || { printf '<h1>Unknown VPN route</h1>'; exit 0; }
            _route_fwmark=$(awk -F= '/^FWMARK/{gsub(/[" \t]/, "", $2); print $2; exit}' \
                "$_vpf" 2>/dev/null)
            [ -n "$_route_fwmark" ] || { printf '<h1>Invalid VPN config</h1>'; exit 0; }
        fi
        { grep -v "^${MAC}	${_dom}	" "$_rules_f" 2>/dev/null
          printf '%s\t%s\tallow\t\t\t%s\n' "$MAC" "$_dom" "${_route:-}"; } \
            > "${_rules_f}.tmp" && mv "${_rules_f}.tmp" "$_rules_f" || true
        _dconf="/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
        _nftset="4#inet#fw4#${_iface}_allow_${_mac_n}_4,6#inet#fw4#${_iface}_allow_${_mac_n}_6"
        [ -n "$_route" ] && \
            _nftset="${_nftset},4#inet#fw4#${_iface}_route_${_mac_n}_${_route}_4,6#inet#fw4#${_iface}_route_${_mac_n}_${_route}_6"
        { grep -v "^nftset=/${_dom}/" "$_dconf" 2>/dev/null
          printf 'nftset=/%s/%s\n' "$_dom" "$_nftset"; } \
            > "${_dconf}.tmp" && mv "${_dconf}.tmp" "$_dconf" || true
        if [ -n "$_route" ]; then
            nft add set inet fw4 "${_iface}_route_${_mac_n}_${_route}_4" \
                '{ type ipv4_addr; flags dynamic,timeout; timeout 24h; }' 2>/dev/null || true
            nft add set inet fw4 "${_iface}_route_${_mac_n}_${_route}_6" \
                '{ type ipv6_addr; flags dynamic,timeout; timeout 24h; }' 2>/dev/null || true
        fi
        /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
        if [ -n "$_route" ]; then
            setsid sh -c "sh /etc/extra-networks/_regen-inspect.sh ${_iface} >/dev/null 2>&1; \
                ACTION=ifup INTERFACE=${_iface} sh /etc/hotplug.d/iface/51-${_iface}-macfilter \
                >/dev/null 2>&1" &
        fi
        _ntfy "Rule added — ${_iface}" default shield \
            "${_DEV_DISPLAY}: ${_dom} allowed on ${_iface}${_route:+ via ${_route} VPN}.

${_actor_info}" \
            "view, Device, ${_DEV_URL}"
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
        case "$_dip" in
            *:*) nft add element inet fw4 "${_iface}_allow_${_mac_n}_6" "{ ${_dip} }" 2>/dev/null || true ;;
            *)   nft add element inet fw4 "${_iface}_allow_${_mac_n}_4" "{ ${_dip} }" 2>/dev/null || true ;;
        esac
        [ -f "$_pending_f" ] && {
            grep -v "^${_dip}	${_dpt}	${_dpr}	" "$_pending_f" \
                > "${_pending_f}.tmp" 2>/dev/null \
                && mv "${_pending_f}.tmp" "$_pending_f" || true
        }
        _ntfy "Rule added — ${_iface}" default shield \
            "${_DEV_DISPLAY}: ${_dip}:${_dpt}/${_dpr} allowed on ${_iface}.

${_actor_info}" \
            "view, Device, ${_DEV_URL}"
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

    allow_lan)
        _dip=$(_get_param "$_params" dst_ip)
        _dpt=$(_get_param "$_params" dst_port)
        _dpr=$(_get_param "$_params" dst_proto)
        _dur=$(_get_param "$_params" duration)
        _valid_ip "$_dip" || { printf '<h1>Invalid IP</h1>'; exit 0; }
        printf '%s' "$_dpt" | grep -qE '^[0-9]{1,5}$' \
            || { printf '<h1>Invalid port</h1>'; exit 0; }
        printf '%s' "$_dpr" | grep -qE '^(tcp|udp)$' \
            || { printf '<h1>Invalid proto</h1>'; exit 0; }
        case "${_dur:-}" in 1h|6h|12h|24h|2d|7d|30d) ;; *) _dur="${DEFAULT_DURATION:-24h}" ;; esac
        _allow_script=$(awk -F= '/^REPO_DIR/{print $2;exit}' "${BASE_DIR}/config" 2>/dev/null)
        sh "${_allow_script}/tools/allow-service.sh" \
            "$_iface" "$_dip" "$_dpr" "$_dpt" "$_dur" lan >/dev/null 2>&1 || true
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
            *:*)
                nft delete element inet fw4 "${_iface}_allow_${_mac_n}_6" \
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

    bulk_revoke)
        _n=$(_get_param "$_params" n)
        printf '%s' "$_n" | grep -qE '^[0-9]+$' || _n=0
        _bi=0
        _need_dnsmasq=no
        _dconf="/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
        while [ "$_bi" -lt "$_n" ]; do
            [ "$(_get_param "$_params" "sel_${_bi}")" = 1 ] || { _bi=$((_bi+1)); continue; }
            _bdst=$(_get_param "$_params"   "dst_${_bi}")
            _bport=$(_get_param "$_params"  "port_${_bi}")
            _bproto=$(_get_param "$_params" "proto_${_bi}")
            [ -f "$_rules_f" ] && {
                grep -v "^${MAC}	${_bdst}	" "$_rules_f" \
                    > "${_rules_f}.tmp" 2>/dev/null \
                    && mv "${_rules_f}.tmp" "$_rules_f" || true
            }
            case "$_bdst" in
                *.*.*.*)
                    nft delete element inet fw4 "${_iface}_allow_${_mac_n}_4" \
                        "{ ${_bdst} }" 2>/dev/null || true ;;
                *:*)
                    nft delete element inet fw4 "${_iface}_allow_${_mac_n}_6" \
                        "{ ${_bdst} }" 2>/dev/null || true ;;
                *)
                    [ -f "$_dconf" ] && {
                        grep -v "/${_bdst}/" "$_dconf" > "${_dconf}.tmp" 2>/dev/null \
                            && mv "${_dconf}.tmp" "$_dconf" || true
                    }
                    _need_dnsmasq=yes ;;
            esac
            _bi=$((_bi+1))
        done
        [ "$_need_dnsmasq" = yes ] && /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    delete)
        _notify_ip="${_DEV_IP:-${_DEV_IP6:-}}"
        _dns=$([ -n "$_notify_ip" ] && nslookup "$_notify_ip" 2>/dev/null \
            | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}' || true)
        _device_detail="Label: ${_DEV_DISPLAY}
IPv4: ${_DEV_IP:-unknown}
IPv6: ${_DEV_IP6:-unknown}
DNS: ${_dns:-unknown}
MAC: ${MAC}"
        _join_history_add "$_iface" deleted "$MAC" "$_DEV_IP" "$_DEV_IP6" \
            "${_DEV_LABEL:-${_dns:-unknown}}" "$_actor_display" \
            "$_actor_ip4" "$_actor_ip6" "$_actor_mac" "${JOIN_HISTORY_RETENTION:-90d}"
        # Remove all state files
        for _f in "$_labels_f" "$_ips_f" "$_ip6s_f" "$_limits_f" "$_rules_f"; do
            [ -f "$_f" ] && { grep -v "^${MAC}	" "$_f" > "${_f}.tmp" 2>/dev/null \
                && mv "${_f}.tmp" "$_f" || true; }
        done
        for _f in "$_join_approved_f" "$_join_denied_f"; do
            [ -f "$_f" ] && { grep -vixF "$MAC" "$_f" > "${_f}.tmp" 2>/dev/null \
                && mv "${_f}.tmp" "$_f" || true; }
        done
        for _f in "$_join_pending_f" "${BASE_DIR}/${_iface}-join-approved-ips"; do
            [ -f "$_f" ] && { grep -v "^${MAC} " "$_f" > "${_f}.tmp" 2>/dev/null \
                && mv "${_f}.tmp" "$_f" || true; }
        done
        # Remove from nft sets
        [ -n "$_DEV_IP" ]  && nft delete element inet fw4 "${_iface}_join_approved_ips"  "{ ${_DEV_IP} }"  2>/dev/null || true
        [ -n "$_DEV_IP6" ] && nft delete element inet fw4 "${_iface}_join_approved_ips6" "{ ${_DEV_IP6} }" 2>/dev/null || true
        nft delete element inet fw4 "${_iface}_join_pending"  "{ ${_DEV_IP} }"  2>/dev/null || true
        nft delete element inet fw4 "${_iface}_join_pending6" "{ ${_DEV_IP6} }" 2>/dev/null || true
        # Remove dnsmasq entries
        rm -f "/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
        rm -f "/etc/dnsmasq.d/${_iface}-dns-${_mac_n}.conf"
        /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
        # Rebuild inspect chain (removes per-device nft sets and rules)
        setsid sh /etc/extra-networks/_regen-inspect.sh "$_iface" >/dev/null 2>&1 &
        _ntfy "Device removed — ${_iface}" default wastebasket \
"${_DEV_DISPLAY} has been removed from ${_iface}.

${_device_detail}

${_actor_info}"
        printf '<meta http-equiv="refresh" content="0;url=/cgi-bin/network?net=%s">' "$(_html "$_iface")"
        exit 0
        ;;

    allowlist_remove)
        [ "${ALLOWLIST:-no}" = yes ] || { printf '<h1>Not applicable</h1>'; exit 0; }
        _allowed_macs_f="${BASE_DIR}/${NET}-allowed-macs"
        { grep -vi "^${MAC}[[:space:]]" "$_allowed_macs_f" 2>/dev/null; } \
            > "${_allowed_macs_f}.tmp" && mv "${_allowed_macs_f}.tmp" "$_allowed_macs_f" || true
        ACTION=ifup INTERFACE="$_iface" sh "/etc/hotplug.d/iface/51-${_iface}-macfilter" \
            >/dev/null 2>&1 || true
        if [ "${DEVICE_CONTROL:-no}" = yes ]; then
            _ip_store="${BASE_DIR}/${NET}-device-ips"
            { grep -v "^${MAC}	" "$_ip_store" 2>/dev/null; } \
                > "${_ip_store}.tmp" && mv "${_ip_store}.tmp" "$_ip_store" || true
            setsid sh -c "sh /etc/extra-networks/_regen-inspect.sh ${_iface} >/dev/null 2>&1; \
                ACTION=ifup INTERFACE=${_iface} sh /etc/hotplug.d/iface/51-${_iface}-macfilter \
                >/dev/null 2>&1" &
        fi
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    bulk_approve)
        _n=$(_get_param "$_params" n)
        printf '%s' "$_n" | grep -qE '^[0-9]+$' && [ "$_n" -le 50 ] \
            || { printf '<h1>Invalid count</h1>'; exit 0; }
        _need_dnsmasq=no
        _need_regen=no
        _bi=0
        while [ "$_bi" -lt "$_n" ]; do
            _bact=$(_get_param "$_params" "act_${_bi}")
            _btype=$(_get_param "$_params" "type_${_bi}")
            _broute=$(printf '%s' "$(_get_param "$_params" "route_${_bi}")" \
                | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            _bdst=$(_get_param "$_params" "dst_${_bi}")
            _bport=$(_get_param "$_params" "port_${_bi}")
            _bproto=$(_get_param "$_params" "proto_${_bi}")
            _bdom=$(printf '%s' "$(_get_param "$_params" "domain_${_bi}")" \
                | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{print tolower($0)}')
            case "$_bact" in
            allow_ip)
                _valid_ip "$_bdst" || { _bi=$((_bi+1)); continue; }
                printf '%s' "$_bport" | grep -qE '^[0-9]{1,5}$' || { _bi=$((_bi+1)); continue; }
                printf '%s' "$_bproto" | grep -qE '^(tcp|udp|icmp)$' || { _bi=$((_bi+1)); continue; }
                _bentry="${MAC}	${_bdst}	allow	${_bport}	${_bproto}"
                grep -qF "$_bentry" "$_rules_f" 2>/dev/null \
                    || printf '%s\n' "$_bentry" >> "$_rules_f"
                case "$_bdst" in
                    *:*) nft add element inet fw4 "${_iface}_allow_${_mac_n}_6" "{ ${_bdst} }" 2>/dev/null || true ;;
                    *)   nft add element inet fw4 "${_iface}_allow_${_mac_n}_4" "{ ${_bdst} }" 2>/dev/null || true ;;
                esac
                [ -f "$_pending_f" ] && {
                    grep -v "^${_bdst}	${_bport}	${_bproto}	" "$_pending_f" \
                        > "${_pending_f}.tmp" 2>/dev/null \
                        && mv "${_pending_f}.tmp" "$_pending_f" || true
                }
                ;;
            allow_domain)
                printf '%s' "$_bdom" | grep -qE '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' \
                    || { _bi=$((_bi+1)); continue; }
                _broute_fwmark=""
                if [ -n "$_broute" ]; then
                    _bvpf="${_split_dir}/vpn-${_broute}.conf"
                    [ -f "$_bvpf" ] || _broute=""
                    [ -n "$_broute" ] && _broute_fwmark=$(awk -F= '/^FWMARK/{gsub(/[" \t]/, "", $2); print $2; exit}' \
                        "$_bvpf" 2>/dev/null)
                fi
                { grep -v "^${MAC}	${_bdom}	" "$_rules_f" 2>/dev/null
                  printf '%s\t%s\tallow\t\t\t%s\n' "$MAC" "$_bdom" "${_broute:-}"; } \
                    > "${_rules_f}.tmp" && mv "${_rules_f}.tmp" "$_rules_f" || true
                _bdconf="/etc/dnsmasq.d/${_iface}-device-${_mac_n}.conf"
                _bnftset="4#inet#fw4#${_iface}_allow_${_mac_n}_4,6#inet#fw4#${_iface}_allow_${_mac_n}_6"
                [ -n "$_broute" ] && \
                    _bnftset="${_bnftset},4#inet#fw4#${_iface}_route_${_mac_n}_${_broute}_4,6#inet#fw4#${_iface}_route_${_mac_n}_${_broute}_6"
                { grep -v "^nftset=/${_bdom}/" "$_bdconf" 2>/dev/null
                  printf 'nftset=/%s/%s\n' "$_bdom" "$_bnftset"; } \
                    > "${_bdconf}.tmp" && mv "${_bdconf}.tmp" "$_bdconf" || true
                if [ -n "$_broute" ]; then
                    nft add set inet fw4 "${_iface}_route_${_mac_n}_${_broute}_4" \
                        '{ type ipv4_addr; flags dynamic,timeout; timeout 24h; }' 2>/dev/null || true
                    nft add set inet fw4 "${_iface}_route_${_mac_n}_${_broute}_6" \
                        '{ type ipv6_addr; flags dynamic,timeout; timeout 24h; }' 2>/dev/null || true
                    _need_regen=yes
                fi
                _need_dnsmasq=yes
                ;;
            deny)
                [ -f "$_pending_f" ] && {
                    grep -v "^${_bdst}	${_bport}	${_bproto}	" "$_pending_f" \
                        > "${_pending_f}.tmp" 2>/dev/null \
                        && mv "${_pending_f}.tmp" "$_pending_f" || true
                }
                ;;
            allow_lan)
                _valid_ip "$_bdst" || { _bi=$((_bi+1)); continue; }
                printf '%s' "$_bport" | grep -qE '^[0-9]{1,5}$' || { _bi=$((_bi+1)); continue; }
                printf '%s' "$_bproto" | grep -qE '^(tcp|udp)$' || { _bi=$((_bi+1)); continue; }
                _bscript=$(awk -F= '/^REPO_DIR/{print $2;exit}' "${BASE_DIR}/config" 2>/dev/null)
                sh "${_bscript}/tools/allow-service.sh" \
                    "$_iface" "$_bdst" "$_bproto" "$_bport" "${DEFAULT_DURATION:-24h}" lan \
                    >/dev/null 2>&1 || true
                ;;
            esac
            _bi=$((_bi+1))
        done
        [ "$_need_dnsmasq" = yes ] && /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
        [ "$_need_regen" = yes ] && setsid sh -c \
            "sh /etc/extra-networks/_regen-inspect.sh ${_iface} >/dev/null 2>&1; \
             ACTION=ifup INTERFACE=${_iface} sh /etc/hotplug.d/iface/51-${_iface}-macfilter \
             >/dev/null 2>&1" & true
        printf '<meta http-equiv="refresh" content="0;url=%s">' "$(_html "$_BACK_URL")"
        exit 0
        ;;

    esac
    printf '<h1>Unknown action</h1>'
    exit 0
fi

# ── GET: render page ──────────────────────────────────────────────────────────

# Scrape logread for new pending connections from this device
if [ -n "$_DEV_IP$_DEV_IP6" ]; then
    _now_ts=$(date +%s)
    logread 2>/dev/null \
    | awk -v ip="$_DEV_IP" -v ip6="$_DEV_IP6" -v iface="$_iface" \
        'index($0, "EXTNET-" iface "-NEW:") {
            src=""; dst=""; dpt=""; proto=""
            for(i=1;i<=NF;i++){
                if($i~/^SRC=/) { sub(/^SRC=/,"",$i); src=$i }
                if($i~/^DST=/) { sub(/^DST=/,"",$i); dst=$i }
                if($i~/^DPT=/) { sub(/^DPT=/,"",$i); dpt=$i }
                if($i~/^PROTO=/) { sub(/^PROTO=/,"",$i); proto=tolower($i) }
            }
            if((src==ip || src==ip6) && dst && dpt && proto) print dst"\t"dpt"\t"proto
        }' \
    | sort -u -t "$(printf '\t')" -k1,3 \
    | while IFS=$(printf '\t') read -r _dst _dpt _proto; do
        grep -qF "${MAC}	${_dst}	" "$_rules_f" 2>/dev/null && continue
        _key="${_dst}	${_dpt}	${_proto}"
        grep -iqF "${_key}	" "$_pending_f" 2>/dev/null \
            || printf '%s\t%s\n' "$_key" "$_now_ts" >> "$_pending_f" 2>/dev/null || true
    done
fi

_is_approved=no
grep -qF "$MAC" "${BASE_DIR}/${_iface}-join-approved" 2>/dev/null && _is_approved=yes

# Build subnet→label map: each prefix maps to the network's display name
_net_map=$(
    _lp=$(ip addr show br-lan 2>/dev/null \
        | awk '/inet /{split($2,a,"/"); sub(/\.[^.]+$/,"",a[1]); print a[1]; exit}')
    [ -n "$_lp" ] && printf '%s\tLAN\n' "$_lp"
    for _nc in "${BASE_DIR}"/*-notify.conf; do
        [ -f "$_nc" ] || continue
        _sn=$(awk -F= '/^SUBNET=/{print $2;exit}' "$_nc" 2>/dev/null)
        _nm=$(awk -F= '/^IFACE_NAME=/{print $2;exit}' "$_nc" 2>/dev/null)
        [ -n "$_sn" ] && [ -n "$_nm" ] || continue
        printf '%s\t%s\n' "$_sn" \
            "$(printf '%s' "$_nm" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
    done
)
_net_label() {
    printf '%s\n' "$_net_map" \
        | awk -F'\t' -v p="${1%.*}" '$1==p{print $2;exit}' \
        | grep . || printf 'Internet'
}

# Collect all blocked/pending connections: label\taction\tdst\tdpt\tproto
_conn_tmp="/tmp/devcgi_conn_$$"
: > "$_conn_tmp"

if [ -n "$_DEV_IP" ]; then
    logread 2>/dev/null \
        | awk -v ip="$_DEV_IP" -v iface="$_iface" \
            'index($0, "EXTNET-2LAN-" iface ":") {
                src=""; dst=""; dpt=""; proto=""
                for(i=1;i<=NF;i++){
                    if($i~/^SRC=/) { sub(/^SRC=/,"",$i); src=$i }
                    if($i~/^DST=/) { sub(/^DST=/,"",$i); dst=$i }
                    if($i~/^DPT=/) { sub(/^DPT=/,"",$i); dpt=$i }
                    if($i~/^PROTO=/) { sub(/^PROTO=/,"",$i); proto=tolower($i) }
                }
                if(src==ip && dst && dpt && proto) print dst"\t"dpt"\t"proto
            }' \
        | sort -t "$(printf '\t')" -u -k1,3 | tail -20 \
        | while IFS=$(printf '\t') read -r _dst _dpt _proto; do
            _dst_slug=$(printf '%s' "$_dst" | sed 's/[.:]/\_/g')
            uci -q get firewall."allow_${_iface}_lan_${_dst_slug}_${_dpt}_${_proto}" \
                >/dev/null 2>&1 && continue
            printf '%s\tlan\t%s\t%s\t%s\n' "$(_net_label "$_dst")" "$_dst" "$_dpt" "$_proto"
          done >> "$_conn_tmp" 2>/dev/null || true
fi

if [ -f "$_pending_f" ]; then
    _cutoff=$(( $(date +%s) - 86400 ))
    awk -F'\t' -v cut="$_cutoff" '$4+0 >= cut' "$_pending_f" \
        > "${_pending_f}.tmp" 2>/dev/null \
        && mv "${_pending_f}.tmp" "$_pending_f" || rm -f "${_pending_f}.tmp"
    while IFS=$(printf '\t') read -r _dst _dpt _proto _ts; do
        [ -z "$_dst" ] && continue
        grep -qF "${MAC}	${_dst}	" "$_rules_f" 2>/dev/null && continue
        printf '%s\tinet\t%s\t%s\t%s\n' "$(_net_label "$_dst")" "$_dst" "$_dpt" "$_proto"
    done < "$_pending_f" >> "$_conn_tmp" 2>/dev/null || true
fi

# Build bulk approval form rows (sorted: LAN first, then inet; unique by dst+port+proto)
# Cap inet rows at 50 most recent to keep the page small
sort -t "$(printf '\t')" -k2,2 -k3,3 -k4,4n -k5,5 -u "$_conn_tmp" \
    > "${_conn_tmp}.s" 2>/dev/null && mv "${_conn_tmp}.s" "$_conn_tmp" || true
_bulk_total=$(awk 'END{print NR+0}' "$_conn_tmp" 2>/dev/null)
if [ "$_bulk_total" -gt 50 ] 2>/dev/null; then
    _bulk_hidden=$(( _bulk_total - 50 ))
    { head -50 "$_conn_tmp"; } > "${_conn_tmp}.t" 2>/dev/null \
        && mv "${_conn_tmp}.t" "$_conn_tmp" || true
else
    _bulk_hidden=0
fi
_bulk_n=$(awk 'END{print NR+0}' "$_conn_tmp" 2>/dev/null)
_bulk_form_rows=""
if [ -s "$_conn_tmp" ]; then
    _ss='font-size:.8rem;padding:.2rem .35rem;border:1px solid #ccc;border-radius:4px'
    _bulk_form_rows=$(
        _i=0
        while IFS=$(printf '\t') read -r _lbl _atype _dst _dpt _proto; do
            _rdns=$(nslookup "$_dst" 2>/dev/null \
                | awk '/name =/{gsub(/\.$/,"",$NF); print $NF; exit}')
            _apex=$(printf '%s' "${_rdns:-}" \
                | awk -F. 'NF>=2{print $(NF-1)"."$NF}')
            printf '<tr><td>%s' "$(_html "$_dst")"
            [ -n "$_rdns" ] \
                && printf '<br><span class="dim" style="font-size:.78rem">%s</span>' \
                    "$(_html "$_rdns")"
            printf '</td><td class="dim">%s/%s</td><td>' "$_dpt" "$_proto"
            case "$_atype" in
            inet)
                printf '<select name="act_%d" style="%s">' "$_i" "$_ss"
                printf '<option value="skip">Skip</option>'
                printf '<option value="allow_ip">Allow IP</option>'
                printf '<option value="allow_domain">Allow domain</option>'
                printf '<option value="deny">Deny</option>'
                printf '</select>'
                ;;
            lan)
                printf '<select name="act_%d" style="%s">' "$_i" "$_ss"
                printf '<option value="skip">Skip</option>'
                printf '<option value="allow_lan">Allow</option>'
                printf '<option value="deny">Remove</option>'
                printf '</select>'
                ;;
            esac
            printf '</td><td>'
            if [ "$_atype" = inet ]; then
                printf '<select name="route_%d" style="%s;margin-right:.35rem"><option value="">WAN</option>%s</select>' \
                    "$_i" "$_ss" "$_vpn_options"
                printf '<input type="text" name="domain_%d" value="%s" placeholder="domain.com" style="%s;width:148px">' \
                    "$_i" "$(_html "$_apex")" "$_ss"
            fi
            printf '<input type="hidden" name="dst_%d"  value="%s">' "$_i" "$(_html "$_dst")"
            printf '<input type="hidden" name="port_%d" value="%s">' "$_i" "$(_html "$_dpt")"
            printf '<input type="hidden" name="proto_%d" value="%s">' "$_i" "$(_html "$_proto")"
            printf '<input type="hidden" name="type_%d" value="%s">' "$_i" "$_atype"
            printf '</td></tr>\n'
            _i=$((_i+1))
        done < "$_conn_tmp"
    )
fi
rm -f "$_conn_tmp"

# Collect DNS queries from dnsmasq log for this device
_dns_tmp="/tmp/devcgi_dns_$$"
: > "$_dns_tmp"
if [ -n "$_DEV_IP" ]; then
    _app_doms=$([ -f "$_rules_f" ] && \
        awk -v m="$MAC" -F'\t' \
            'tolower($1)==tolower(m) && $4=="" && $3=="allow"{print tolower($2)}' \
            "$_rules_f" 2>/dev/null || true)
    logread 2>/dev/null \
    | awk -v ip="$_DEV_IP" '
        (index($0,"query[A]")||index($0,"query[AAAA]")) && index($0,"from " ip) {
            n=split($0,f," ")
            for(i=1;i<=n;i++) if(f[i]=="query[A]"||f[i]=="query[AAAA]") {dom=f[i+1];break}
            if(!dom||index(dom,".arpa")||dom~/^[0-9.]+$/) next
            print dom
        }
    ' | awk '{print tolower($0)}' | sort | uniq -c | sort -rn | head -50 \
    | while read -r _cnt _dom; do
        [ -z "$_dom" ] && continue
        printf '%s\n' "$_app_doms" | grep -qxF "$_dom" 2>/dev/null && continue
        printf '%s\t%s\n' "$_cnt" "$_dom" >> "$_dns_tmp"
    done
fi
_dns_n=$(awk 'END{print NR+0}' "$_dns_tmp" 2>/dev/null)

# Threat intelligence: local blocklists + Spamhaus DBL; 24h file cache per apex domain
_threat_dir="${BASE_DIR}/threat-cache"
mkdir -p "$_threat_dir" 2>/dev/null || true

_threat_apex() {
    printf '%s' "$1" | awk -F. '{
        n=NF
        if(n>=3 && ($n=="uk"||$n=="au"||$n=="br"||$n=="nz"||$n=="za") \
           && $(n-1)~/^(co|com|org|net|gov|edu|ac)$/)
            {print $(n-2)"."$(n-1)"."$n}
        else if(n>=2) {print $(n-1)"."$n}
        else {print $0}
    }'
}

_threat_check() {
    _tf="$1" _ta="$2" _tt=""
    # Local torrent/adult/ad blocklists (nftset=/domain/... format)
    grep -qF "/${_tf}/" /etc/dnsmasq.d/bg_torrentsites.conf 2>/dev/null \
        || grep -qF "/${_ta}/" /etc/dnsmasq.d/bg_torrentsites.conf 2>/dev/null \
        && _tt="${_tt:+${_tt},}Torrent"
    grep -qF "/${_tf}/" /etc/dnsmasq.d/bg_pornsites.conf 2>/dev/null \
        || grep -qF "/${_ta}/" /etc/dnsmasq.d/bg_pornsites.conf 2>/dev/null \
        && _tt="${_tt:+${_tt},}Adult"
    [ -s /etc/dnsmasq.d/adb_list.overall ] && {
        grep -qF "/${_tf}/" /etc/dnsmasq.d/adb_list.overall 2>/dev/null \
            || grep -qF "/${_ta}/" /etc/dnsmasq.d/adb_list.overall 2>/dev/null \
            && _tt="${_tt:+${_tt},}Ad/Tracker"
    }
    # Spamhaus DBL: returns 127.0.1.x for listed domains, 127.255.255.254 or NXDOMAIN if clean
    _dbl=$(nslookup "${_ta}.dbl.spamhaus.org" 2>/dev/null \
        | awk '/^Address/ && !/127\.0\.0\.1/ && !/127\.255\.255/{print $2; exit}')
    case "$_dbl" in
        127.0.1.2)   _tt="${_tt:+${_tt},}Spam" ;;
        127.0.1.4)   _tt="${_tt:+${_tt},}Phishing" ;;
        127.0.1.5)   _tt="${_tt:+${_tt},}Malware" ;;
        127.0.1.6)   _tt="${_tt:+${_tt},}Botnet C&C" ;;
        127.0.1.10*) _tt="${_tt:+${_tt},}Abused Domain" ;;
    esac
    printf '%s' "$_tt"
}

_threat_any_new=0
# Pre-fetch for unapproved queried domains
if [ -s "$_dns_tmp" ]; then
    while IFS=$(printf '\t') read -r _frc _frd; do
        [ -z "$_frd" ] && continue
        _fra=$(_threat_apex "$_frd")
        _frf="${_threat_dir}/${_fra}"
        _frage=$(( $(date +%s) - $(stat -c '%Y' "$_frf" 2>/dev/null || echo 0) ))
        if [ ! -f "$_frf" ] || [ "$_frage" -ge 86400 ]; then
            _threat_any_new=1
            (_threat_check "$_frd" "$_fra" > "${_frf}.tmp" \
                && mv "${_frf}.tmp" "$_frf" || rm -f "${_frf}.tmp") &
        fi
    done < "$_dns_tmp"
fi
# Pre-fetch for already-approved domain rules (so Approved Domains section shows threat info)
if [ -f "$_rules_f" ]; then
    awk -v m="$MAC" -F'\t' 'tolower($1)==tolower(m) && $4=="" && $3=="allow"{print $2}' \
        "$_rules_f" 2>/dev/null \
    | while read -r _adm; do
        [ -z "$_adm" ] && continue
        _fra=$(_threat_apex "$_adm")
        _frf="${_threat_dir}/${_fra}"
        _frage=$(( $(date +%s) - $(stat -c '%Y' "$_frf" 2>/dev/null || echo 0) ))
        if [ ! -f "$_frf" ] || [ "$_frage" -ge 86400 ]; then
            _threat_any_new=1
            (_threat_check "$_adm" "$_fra" > "${_frf}.tmp" \
                && mv "${_frf}.tmp" "$_frf" || rm -f "${_frf}.tmp") &
        fi
    done
fi
[ "$_threat_any_new" = 1 ] && { sleep 4; wait; } 2>/dev/null || true

_dns_rows=""
if [ -s "$_dns_tmp" ]; then
    _ss='font-size:.8rem;padding:.2rem .35rem;border:1px solid #ccc;border-radius:4px'
    _dns_rows=$(
        _i=0
        while IFS=$(printf '\t') read -r _cnt _dom; do
            [ -z "$_dom" ] && continue
            _dapx=$(_threat_apex "$_dom")
            _dcf="${_threat_dir}/${_dapx}"
            if [ -f "$_dcf" ]; then
                _dtags=$(cat "$_dcf" 2>/dev/null)
                if [ -z "$_dtags" ]; then
                    _drep='<span class="dim">—</span>'
                else
                    _ts='font-size:.7rem;font-weight:700;padding:.1rem .35rem;border-radius:999px;color:#fff;margin-right:.2rem'
                    _drep=$(printf '%s' "$_dtags" | awk -F, -v ts="$_ts" '{
                        for(i=1;i<=NF;i++){
                            t=$i
                            if(t~/Malware|Phishing|Botnet/) c="#b71c1c"
                            else if(t~/Spam|Abused/)        c="#e65100"
                            else if(t~/Torrent/)            c="#1565c0"
                            else if(t~/Adult/)              c="#6a1b9a"
                            else if(t~/Ad.Tracker/)         c="#f57c00"
                            else                            c="#555"
                            printf "<span style=\"%s;background:%s\">%s</span>",ts,c,t
                        }
                    }')
                fi
            else
                _drep='<span class="dim">…</span>'
            fi
            printf '<tr><td>%s<br>%s</td>' "$(_html "$_dom")" "$_drep"
            printf '<td class="dim">%s&times;</td><td>' "$_cnt"
            printf '<select name="act_%d" style="%s">' "$_i" "$_ss"
            printf '<option value="skip">Skip</option>'
            printf '<option value="allow_domain">Allow</option>'
            printf '</select></td><td>'
            printf '<select name="route_%d" style="%s;margin-right:.35rem">' "$_i" "$_ss"
            printf '<option value="">WAN</option>%s</select>' "$_vpn_options"
            printf '<input type="hidden" name="domain_%d" value="%s">' "$_i" "$(_html "$_dom")"
            printf '<input type="hidden" name="type_%d" value="dns">' "$_i"
            printf '</td></tr>\n'
            _i=$((_i+1))
        done < "$_dns_tmp"
    )
fi
rm -f "$_dns_tmp"

# Build combined active rules (domain allows + IP/port rules) into temp file
_arules_tmp="/tmp/devcgi_ar_$$"
{
    [ -f "$_rules_f" ] && awk -v m="$MAC" -F'\t' '
        tolower($1)==tolower(m) && $3=="allow" && $4=="" {
            print "dom\t"$2"\t\t\t"(NF>=6 ? $6 : "")"\tallow"
        }
        tolower($1)==tolower(m) && $4!="" {
            print "ip\t"$2"\t"$4"\t"$5"\t"(NF>=6 ? $6 : "")"\t"$3
        }
    ' "$_rules_f" 2>/dev/null
} > "$_arules_tmp" 2>/dev/null || true

_ts_badge='font-size:.7rem;font-weight:700;padding:.1rem .35rem;border-radius:999px;color:#fff;margin-right:.2rem'
_all_rules_n=$(awk 'END{print NR+0}' "$_arules_tmp" 2>/dev/null)
_all_rules_rows=""
if [ -s "$_arules_tmp" ]; then
    _all_rules_rows=$(
        _ri=0
        while IFS=$(printf '\t') read -r _rtype _rdst _rport _rproto _rroute _ract; do
            [ -z "$_rdst" ] && continue
            _rvlabel="${_rroute:-WAN}"
            _rtrep='<span class="dim">—</span>'
            if [ "$_rtype" = dom ]; then
                _drapx=$(_threat_apex "$_rdst")
                _drcf="${_threat_dir}/${_drapx}"
                if [ -f "$_drcf" ]; then
                    _drtags=$(cat "$_drcf" 2>/dev/null)
                    [ -n "$_drtags" ] && _rtrep=$(printf '%s' "$_drtags" | awk -F, -v ts="$_ts_badge" '{
                        for(i=1;i<=NF;i++){
                            t=$i
                            if(t~/Malware|Phishing|Botnet/) c="#b71c1c"
                            else if(t~/Spam|Abused/)        c="#e65100"
                            else if(t~/Torrent/)            c="#1565c0"
                            else if(t~/Adult/)              c="#6a1b9a"
                            else if(t~/Ad.Tracker/)         c="#f57c00"
                            else                            c="#555"
                            printf "<span style=\"%s;background:%s\">%s</span>",ts,c,t
                        }
                    }')
                else
                    _rtrep='<span class="dim">…</span>'
                fi
            fi
            printf '<tr><td>'
            if [ "$_rtype" = dom ]; then
                printf '<label style="display:flex;align-items:center;gap:.4rem">'
                printf '<input type="checkbox" name="sel_%d" value="1">%s</label>' \
                    "$_ri" "$(_html "$_rdst")"
            else
                _tc=$([ "$_ract" = allow ] && echo "tag-allow" || echo "tag-deny")
                _tl=$([ "$_ract" = allow ] && echo "Allow" || echo "Deny")
                printf '<label style="display:flex;align-items:center;gap:.4rem">'
                printf '<input type="checkbox" name="sel_%d" value="1">' "$_ri"
                printf '<span>%s <span class="%s" style="font-size:.7rem">%s</span></span></label>' \
                    "$(_html "$_rdst")" "$_tc" "$_tl"
            fi
            printf '<input type="hidden" name="dst_%d"   value="%s">' "$_ri" "$(_html "$_rdst")"
            printf '<input type="hidden" name="port_%d"  value="%s">' "$_ri" "$(_html "${_rport:-}")"
            printf '<input type="hidden" name="proto_%d" value="%s">' "$_ri" "$(_html "${_rproto:-}")"
            printf '</td>'
            if [ "$_rtype" = dom ]; then
                printf '<td class="dim">—</td>'
            else
                printf '<td class="dim">%s/%s</td>' "$_rport" "$_rproto"
            fi
            printf '<td class="dim">%s</td><td>%s</td>' "$(_html "$_rvlabel")" "$_rtrep"
            printf '</tr>\n'
            _ri=$((_ri+1))
        done < "$_arules_tmp"
    )
fi
rm -f "$_arules_tmp"

_approval_controls=""
_approval_row=""
if [ "${JOIN_APPROVAL:-no}" = yes ]; then
if [ "$_JOIN_STATE" != Approved ] && [ -n "$_JOIN_IP" ]; then
    _approval_controls="${_approval_controls}$(cat <<HTML
<form method="POST" action="/cgi-bin/approve-join">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="ip" value="$(_html "$_JOIN_IP")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="host" value="$(_html "$_DEV_LABEL")">
<input type="hidden" name="action" value="approve">
<button class="btn-ok" type="submit">Approve</button>
</form>
HTML
)"
fi
if [ "$_JOIN_STATE" != Approved ] && [ "$_JOIN_STATE" != Denied ] && [ -n "$_JOIN_IP" ]; then
    _approval_controls="${_approval_controls}$(cat <<HTML
<form method="POST" action="/cgi-bin/approve-join">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="ip" value="$(_html "$_JOIN_IP")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="host" value="$(_html "$_DEV_LABEL")">
<input type="hidden" name="action" value="deny">
<button class="btn-deny" type="submit">Deny</button>
</form>
HTML
)"
fi
if [ "$_JOIN_STATE" = Approved ]; then
    _approval_controls="${_approval_controls}$(cat <<HTML
<form method="POST" action="/cgi-bin/device" onsubmit="return confirm('Revoke internet approval for $(_html "$_DEV_DISPLAY")?')">
<input type="hidden" name="net" value="$(_html "$NET")">
<input type="hidden" name="mac" value="$(_html "$MAC")">
<input type="hidden" name="action" value="revoke_join_approval">
<button class="btn-danger" type="submit">Revoke approval</button>
</form>
HTML
)"
fi
_approval_row=$(cat <<HTML
<div class="row"><span class="lbl">Join approval</span><span class="val $([ "$_JOIN_STATE" = Approved ] && echo ok || echo warn)">$(_html "$_JOIN_STATE")</span></div>
<div class="row"><span class="lbl">Actions</span><span class="val actions">${_approval_controls:-No action available}</span></div>
HTML
)
fi  # JOIN_APPROVAL=yes

_allowlist_row=""
if [ "${ALLOWLIST:-no}" = yes ]; then
    _al_macs_f="${BASE_DIR}/${NET}-allowed-macs"
    if grep -qiE "^${MAC}[[:space:]]" "$_al_macs_f" 2>/dev/null; then
        _al_ip=$(awk -v m="$MAC" 'tolower($1)==tolower(m){print $2; exit}' "$_al_macs_f" 2>/dev/null)
        _allowlist_row=$(cat <<HTML
<div class="row"><span class="lbl">Allowlist</span><span class="val actions"><span class="ok">Allowed${_al_ip:+ ($(_html "$_al_ip"))}</span><form method="POST" action="/cgi-bin/device" onsubmit="return confirm('Remove $(_html "$_DEV_DISPLAY") from allowlist?')"><input type="hidden" name="net" value="$(_html "$NET")"><input type="hidden" name="mac" value="$(_html "$MAC")"><input type="hidden" name="action" value="allowlist_remove"><button class="btn-danger" type="submit">Remove</button></form></span></div>
HTML
)
    else
        _al_btn_attr=""
        [ -z "$_DEV_LABEL" ] && _al_btn_attr=' disabled title="Set a label first"'
        _allowlist_row=$(cat <<HTML
<div class="row"><span class="lbl">Allowlist</span><span class="val actions"><span class="warn">Not on allowlist</span><form method="POST" action="/cgi-bin/approve-join"><input type="hidden" name="net" value="$(_html "$NET")"><input type="hidden" name="mac" value="$(_html "$MAC")"><input type="hidden" name="action" value="allowlist_add"><input type="hidden" name="redirect" value="$(_html "$_BACK_URL")"><input type="hidden" name="label" value="$(_html "$_DEV_LABEL")"><button class="btn-ok" type="submit"${_al_btn_attr}>Add to allowlist</button></form></span></div>
HTML
)
    fi
fi

# Build "networks" row — all networks where this MAC has been seen (current network first)
_networks_html="<a href=\"/cgi-bin/device?net=${_iface}&mac=${MAC}\" class=\"ok\">${_iface}</a>"
for _ohf in "${BASE_DIR}"/*-join-history; do
    [ -f "$_ohf" ] || continue
    _on="${_ohf##*/}"; _on="${_on%-join-history}"
    [ "$_on" = "$_iface" ] && continue
    awk -v m="$MAC" -F'\t' 'tolower($4)==tolower(m){found=1} END{exit !found}' "$_ohf" 2>/dev/null || continue
    _networks_html="${_networks_html} · <a href=\"/cgi-bin/device?net=${_on}&mac=${MAC}\">${_on}</a>"
done
for _olf in "${BASE_DIR}"/*-device-labels; do
    [ -f "$_olf" ] || continue
    _on="${_olf##*/}"; _on="${_on%-device-labels}"
    [ "$_on" = "$_iface" ] && continue
    case "$_networks_html" in *"?net=${_on}&"*) continue ;; esac
    awk -v m="$MAC" 'tolower($1)==tolower(m){found=1} END{exit !found}' "$_olf" 2>/dev/null || continue
    _networks_html="${_networks_html} · <a href=\"/cgi-bin/device?net=${_on}&mac=${MAC}\">${_on}</a>"
done
_dhcp_ip=$(awk -v m="$MAC" 'tolower($2)==tolower(m){print $3; exit}' /tmp/dhcp.leases 2>/dev/null)
if [ -n "$_dhcp_ip" ]; then
    _on_managed=no
    for _onc in "${BASE_DIR}"/*-notify.conf; do
        [ -f "$_onc" ] || continue
        _osub=$(awk -F= '/^SUBNET=/{print $2;exit}' "$_onc")
        [ -n "$_osub" ] && case "$_dhcp_ip" in "${_osub}."*) _on_managed=yes; break;; esac
    done
    if [ "$_on_managed" = no ]; then
        _networks_html="${_networks_html} · <a href=\"/cgi-bin/device?net=lan&mac=${MAC}\">lan</a> <span class=\"dim\">$(_html "$_dhcp_ip")</span>"
    fi
fi
_networks_row="<div class=\"row\"><span class=\"lbl\">Networks</span><span class=\"val\">${_networks_html}</span></div>"

# Online status via ARP/NDP neighbour table
_online_cls=dim; _online_text=Offline
if [ -n "$_DEV_IP" ]; then
    _ns=$(ip neigh show "$_DEV_IP" dev "br-${_iface}" 2>/dev/null | awk '{print $NF; exit}')
    case "$_ns" in REACHABLE|DELAY|PROBE) _online_cls=ok; _online_text=Online ;; esac
fi
if [ "$_online_text" != Online ] && [ -n "$_DEV_IP6" ]; then
    _ns=$(ip neigh show "$_DEV_IP6" dev "br-${_iface}" 2>/dev/null | awk '{print $NF; exit}')
    case "$_ns" in REACHABLE|DELAY|PROBE) _online_cls=ok; _online_text=Online ;; esac
fi

# Manufacturer via OUI lookup; locally administered (randomized) MACs have no OUI entry.
# Checks 36-bit (9 hex), 28-bit (7 hex), and 24-bit (6 hex) prefixes — longest match wins.
_mac_hex=$(printf '%s' "$MAC" | tr -d ':' | tr 'abcdef' 'ABCDEF')
_mac_first=$(printf '%d' "0x${_mac_hex%??????????}")
if [ $(( _mac_first & 2 )) -ne 0 ]; then
    _MANUFACTURER="Randomized MAC"
else
    _MANUFACTURER=$(awk -F'\t' -v m="$_mac_hex" '
        { l = length($1) }
        l == 9 && substr(m,1,9) == $1 && best < 9 { r = $2; best = 9 }
        l == 7 && substr(m,1,7) == $1 && best < 7 { r = $2; best = 7 }
        l == 6 && substr(m,1,6) == $1 && best < 6 { r = $2; best = 6 }
        END { print r }
    ' "${BASE_DIR}/oui.txt" 2>/dev/null || true)
fi

# History stats: last seen, first seen, join count across all networks
# shellcheck disable=SC2086
_hist_stats=$(awk -v m="$MAC" -F'\t' '
    tolower($4)==tolower(m){
        cnt++
        if(mn==""||$1+0<mn+0){mn=$1;mnw=$2}
        if(mx==""||$1+0>mx+0){mx=$1;mxw=$2}
    }
    END{print mx"\t"mxw"\t"mn"\t"mnw"\t"cnt}
' ${BASE_DIR}/*-join-history 2>/dev/null || true)
_JOIN_COUNT=$(printf '%s' "$_hist_stats" | awk -F'\t' '{print $5}')
_last_seen_val=""; _first_seen_val=""
for _ls_hf in "${BASE_DIR}"/*-join-history; do
    [ -f "$_ls_hf" ] || continue
    _ls_net="${_ls_hf##*/}"; _ls_net="${_ls_net%-join-history}"
    _ls_stats=$(awk -v m="$MAC" -F'\t' '
        tolower($4)==tolower(m){
            if(mn==""||$1+0<mn+0){mn=$1;mnw=$2}
            if(mx==""||$1+0>mx+0){mx=$1;mxw=$2}
        }
        END{print mx+0"\t"mn+0"\t"mnw}
    ' "$_ls_hf" 2>/dev/null || true)
    _ls_last_ts=$(printf '%s' "$_ls_stats" | awk -F'\t' '{print $1}')
    _ls_first_fmt=$(printf '%s' "$_ls_stats" | awk -F'\t' '{print $3}')
    [ -z "$_ls_last_ts" ] || [ "$_ls_last_ts" = 0 ] && continue
    if [ "$_online_text" = Online ] && [ "$_ls_net" = "$_iface" ]; then
        _ls_rel='<span class="ok">Now</span>'
    else
        _ls_rel=$(_rel_time "$_ls_last_ts")
    fi
    _sep=$([ -n "$_last_seen_val" ] && printf '<br>' || true)
    _ls_link="<a href=\"/cgi-bin/network?net=${_ls_net}&amp;mac=${MAC}\" class=\"dim\">${_ls_net}</a>"
    _last_seen_val="${_last_seen_val}${_sep}${_ls_link}&ensp;${_ls_rel}"
    _first_seen_val="${_first_seen_val}${_sep}${_ls_link}&ensp;${_ls_first_fmt:-—}"
done
[ -z "$_last_seen_val" ] && _last_seen_val='<span class="dim">Unknown</span>'
[ -z "$_first_seen_val" ] && _first_seen_val='<span class="dim">Unknown</span>'

# Lease status from /tmp/dhcp.leases (epoch mac ip hostname)
_lease_line=$(awk -v m="$MAC" 'tolower($2)==tolower(m){print; exit}' /tmp/dhcp.leases 2>/dev/null || true)
_LEASE_STATUS="No lease"
if [ -n "$_lease_line" ]; then
    _lease_exp=$(printf '%s' "$_lease_line" | awk '{print $1}')
    if [ "${_lease_exp:-0}" = 0 ]; then
        _LEASE_STATUS="Static (no expiry)"
    else
        _lease_diff=$(( _lease_exp - $(date +%s) ))
        if   [ "$_lease_diff" -le 0 ];     then _LEASE_STATUS="Expired"
        elif [ "$_lease_diff" -lt 3600 ];  then _LEASE_STATUS="Expires in $(( _lease_diff / 60 ))m"
        elif [ "$_lease_diff" -lt 86400 ]; then _LEASE_STATUS="Expires in $(( _lease_diff / 3600 ))h"
        else                                    _LEASE_STATUS="Expires in $(( _lease_diff / 86400 ))d"
        fi
    fi
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
.net-hdr td{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:#555;font-weight:700;background:#ececec;border-top:2px solid #ddd;padding:.3rem .5rem}
.host-hdr td{background:#f5f5f5;font-weight:600;border-bottom:1px solid #e0e0e0;border-top:1px solid #e8e8e8}
a{color:#1976d2;text-decoration:none}
form{display:inline}
button{font-size:.75rem;padding:.15rem .45rem;cursor:pointer;background:#1976d2;
       color:#fff;border:none;border-radius:4px}
.actions{display:inline-flex;gap:.25rem;align-items:center;justify-content:flex-end;flex-wrap:wrap}
.actions form{display:inline-flex}
.actions button{font-weight:600;padding:.22rem .55rem;border-radius:999px;box-shadow:0 1px 2px rgba(0,0,0,.12)}
.btn-ok{background:#2e7d32}
.btn-deny{background:#c62828}
.btn-danger{background:#c62828}
button:disabled{opacity:.4;cursor:not-allowed}
input[type=text],input[type=number]{font-size:.875rem;padding:.3rem .5rem;
   border:1px solid #ccc;border-radius:4px}
.irow{display:flex;gap:.5rem;align-items:center;margin:.4rem 0}
.tag-allow{color:#2e7d32;font-weight:600}.tag-deny{color:#c62828;font-weight:600}
.badge{font-size:.7rem;font-weight:700;padding:.15rem .45rem;border-radius:999px;
       text-transform:uppercase;letter-spacing:.04em;color:#fff}
.badge-approved{background:#2e7d32}.badge-denied{background:#c62828}
.badge-revoked{background:#e65100}.badge-connected{background:#1565c0}
.badge-disconnected{background:#757575}.badge-deleted{background:#37474f}
.badge-labelled{background:#6a1b9a}
</style></head><body>
<h1>$(_html "$_DEV_DISPLAY")</h1>
<div class="sub">$(_html "$_iface") &nbsp;·&nbsp; $(_html "$MAC") &nbsp;·&nbsp; <a href="/cgi-bin/status">Dashboard</a></div>

<h2>Device</h2>
<div class="card">
<div class="row"><span class="lbl">MAC</span><span class="val">$(_html "$MAC")</span></div>
<div class="row"><span class="lbl">Manufacturer</span><span class="val dim">${_MANUFACTURER:----}</span></div>
<div class="row"><span class="lbl">Label</span><span class="val"><form method="POST" action="/cgi-bin/device" style="display:inline-flex;gap:.3rem;align-items:center"><input type="hidden" name="net" value="$(_html "$NET")"><input type="hidden" name="mac" value="$(_html "$MAC")"><input type="hidden" name="action" value="set_label"><input type="text" name="label" value="$(_html "$_DEV_LABEL")" placeholder="e.g. Living Room TV" maxlength="40" style="width:160px"><button type="submit">Save</button></form></span></div>
<div class="row"><span class="lbl">Last seen</span><span class="val" style="text-align:right;line-height:1.7">${_last_seen_val}</span></div>
<div class="row"><span class="lbl">First seen</span><span class="val" style="text-align:right;line-height:1.7;font-weight:400;color:#555">${_first_seen_val}</span></div>
<div class="row"><span class="lbl">Tracked IPv4</span><span class="val">${_DEV_IP:----}</span></div>
<div class="row"><span class="lbl">Tracked IPv6</span><span class="val">${_DEV_IP6:----}</span></div>
<div class="row"><span class="lbl">DHCP hostname</span><span class="val">${_DEV_HN:----}</span></div>
<div class="row"><span class="lbl">Lease</span><span class="val">$(_html "$_LEASE_STATUS")</span></div>
<div class="row"><span class="lbl">Network</span><span class="val">$(_html "$_iface")</span></div>
<div class="row"><span class="lbl">DNS names</span><span class="val" style="text-align:right">${_DEV_DNS_DISPLAY}</span></div>
<div class="row"><span class="lbl">Total joins</span><span class="val">${_JOIN_COUNT:----}</span></div>
${_networks_row}
${_allowlist_row}
${_approval_row}
</div>

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
<select name="route" style="font-size:.875rem;padding:.3rem .5rem;border:1px solid #ccc;border-radius:4px">
<option value="">WAN (default)</option>
${_vpn_options}
</select>
<button type="submit">Allow</button>
</div>
</form>

<h2>Connection approvals</h2>
HTML

if [ -n "$_bulk_form_rows" ]; then
    printf '<form method="POST" action="/cgi-bin/device">\n'
    printf '<input type="hidden" name="net"    value="%s">\n' "$(_html "$NET")"
    printf '<input type="hidden" name="mac"    value="%s">\n' "$(_html "$MAC")"
    printf '<input type="hidden" name="action" value="bulk_approve">\n'
    printf '<input type="hidden" name="n"      value="%s">\n' "$_bulk_n"
    printf '<table><tr><th>Destination</th><th>Port/Proto</th><th>Action</th><th>Route</th></tr>\n'
    printf '%s\n' "$_bulk_form_rows"
    printf '</table>\n'
    printf '<div class="irow" style="margin-top:.75rem"><button type="submit">Apply</button></div>\n'
    printf '</form>\n'
    printf '<script>(function(){'
    printf 'document.querySelectorAll("select[name^=\\"act_\\"]").forEach(function(s){'
    printf 'var i=s.name.slice(4);'
    printf 'var d=document.querySelector("input[type=text][name=\\"domain_"+i+"\\"]");'
    printf 'if(!d)return;'
    printf 'function u(){d.style.display=s.value==="allow_domain"?"":"none"}'
    printf 's.addEventListener("change",u);u();});'
    printf '})()</script>\n'
[ "$_bulk_hidden" -gt 0 ] 2>/dev/null && \
    printf '<p class="dim" style="margin-top:.4rem">…and %d more older entries not shown.</p>\n' \
        "$_bulk_hidden"
else
    printf '<p class="dim">No pending connections.</p>\n'
fi

printf '<h2>DNS query history</h2>\n'
if [ -n "$_dns_rows" ]; then
    printf '<form method="POST" action="/cgi-bin/device">\n'
    printf '<input type="hidden" name="net"    value="%s">\n' "$(_html "$NET")"
    printf '<input type="hidden" name="mac"    value="%s">\n' "$(_html "$MAC")"
    printf '<input type="hidden" name="action" value="bulk_approve">\n'
    printf '<input type="hidden" name="n"      value="%s">\n' "$_dns_n"
    printf '<table><tr><th>Domain</th><th>Queries</th><th>Action</th><th>Route</th></tr>\n'
    printf '%s\n' "$_dns_rows"
    printf '</table>\n'
    printf '<div class="irow" style="margin-top:.75rem"><button type="submit">Apply</button></div>\n'
    printf '</form>\n'
else
    if [ -z "$_DEV_IP" ]; then
        printf '<p class="dim">No DNS queries logged (device IP unknown).</p>\n'
    elif [ -n "$_app_doms" ]; then
        printf '<p class="dim">All recent DNS queries are already in Active rules.</p>\n'
    else
        printf '<p class="dim">No DNS queries logged yet.</p>\n'
    fi
fi

printf '<h2>Active rules</h2>\n'
if [ -n "$_all_rules_rows" ]; then
    printf '<form method="POST" action="/cgi-bin/device">\n'
    printf '<input type="hidden" name="net"    value="%s">\n' "$(_html "$NET")"
    printf '<input type="hidden" name="mac"    value="%s">\n' "$(_html "$MAC")"
    printf '<input type="hidden" name="action" value="bulk_revoke">\n'
    printf '<input type="hidden" name="n"      value="%s">\n' "$_all_rules_n"
    printf '<table><tr>'
    printf '<th><input type="checkbox" title="Select all" onchange="this.form.querySelectorAll('"'"'input[name^=sel_]'"'"').forEach(function(c){c.checked=this.checked},this)"></th>'
    printf '<th>Rule</th><th>Port/Proto</th><th>Via</th><th>Threat</th>'
    printf '</tr>\n'
    printf '%s\n' "$_all_rules_rows"
    printf '</table>\n'
    printf '<div class="irow" style="margin-top:.75rem">'
    printf '<button type="submit" class="btn-danger">Revoke selected</button>'
    printf '</div>\n'
    printf '</form>\n'
else
    printf '<p class="dim">No active rules.</p>\n'
fi

printf '<h2>History</h2>\n'
_history_html=""
# shellcheck disable=SC2086
set -- ${BASE_DIR}/*-join-history
if [ -f "$1" ]; then
    _history_html=$(awk -v mac="$MAC" -v base="${BASE_DIR}/" -F'\t' '
    function h(s,  t){t=s;gsub(/&/,"\\&amp;",t);gsub(/</,"\\&lt;",t);gsub(/>/,"\\&gt;",t);gsub(/"/,"\\&quot;",t);return t}
    BEGIN{
        while((getline ln<"/tmp/dhcp.leases")>0){split(ln,a," ");if(a[3]!=""&&a[2]!="")lm[a[3]]=a[2]}
        while(("ip neigh show" | getline ln)>0){n2=split(ln,a," ");for(i=1;i<n2;i++)if(a[i]=="lladdr"){arp[a[1]]=a[i+1];break}}
        bcls["approved"]="approved";bcls["denied"]="denied";bcls["revoked"]="revoked"
        bcls["connected"]="connected";bcls["disconnected"]="disconnected";bcls["deleted"]="deleted"
        bcls["labelled"]="labelled"
        blbl["approved"]="Approved";blbl["denied"]="Denied";blbl["revoked"]="Revoked"
        blbl["connected"]="Connected";blbl["disconnected"]="Disconnected";blbl["deleted"]="Deleted"
        blbl["labelled"]="Labelled"
    }
    tolower($4)==tolower(mac){
        fn=FILENAME;sub(base,"",fn);sub(/-join-history$/,"",fn)
        n++;rts[n]=$1;rw[n]=$2;ra[n]=$3;ri4[n]=$5;ri6[n]=$6;rh[n]=$7;rac[n]=$8;raip[n]=$9;rmac[n]=$11;rnet[n]=fn
    }
    END{
        for(i=1;i<=n;i++){
            mx=i
            for(j=i+1;j<=n;j++)if(rts[j]>rts[mx])mx=j
            if(mx!=i){
                tmp=rts[i];rts[i]=rts[mx];rts[mx]=tmp
                tmp=rw[i];rw[i]=rw[mx];rw[mx]=tmp
                tmp=ra[i];ra[i]=ra[mx];ra[mx]=tmp
                tmp=ri4[i];ri4[i]=ri4[mx];ri4[mx]=tmp
                tmp=ri6[i];ri6[i]=ri6[mx];ri6[mx]=tmp
                tmp=rh[i];rh[i]=rh[mx];rh[mx]=tmp
                tmp=rac[i];rac[i]=rac[mx];rac[mx]=tmp
                tmp=raip[i];raip[i]=raip[mx];raip[mx]=tmp
                tmp=rmac[i];rmac[i]=rmac[mx];rmac[mx]=tmp
                tmp=rnet[i];rnet[i]=rnet[mx];rnet[mx]=tmp
            }
        }
        lim=(n>20)?20:n
        for(i=1;i<=lim;i++){
            act=ra[i];actor=rac[i];host=rh[i];ip6=ri6[i];amac=rmac[i];aip4=raip[i];net=rnet[i]
            if(amac==""&&aip4!=""&&aip4 in lm)amac=lm[aip4]
            if(amac==""&&aip4!=""&&aip4 in arp)amac=arp[aip4]
            if(actor==""&&host!="")actor=host
            cls=(act in bcls)?bcls[act]:"untracked"
            lbl=(act in blbl)?blbl[act]:h(act)
            if(amac!="")by="<a href=\"/cgi-bin/device?net=lan&mac="h(amac)"\">"h(amac)"</a>"
            else by=h(actor!=""?actor:"unknown")
            if(act=="labelled")
                dcell="<td><span class=\"badge badge-labelled\">Labelled</span>"(host!=""?"<br><span class=\"dim\" style=\"font-size:.82rem\">"h(host)"</span>":"")  "</td>"
            else
                dcell="<td><span class=\"badge badge-"cls"\">"lbl"</span></td>"
            printf "<tr><td class=\"dim\">%s</td>%s<td>%s</td><td>%s</td><td>%s</td><td class=\"dim\">%s</td></tr>\n",\
                h(rw[i]),dcell,h(net),h(ri4[i]!=""?ri4[i]:"—"),h(ip6!=""?ip6:"—"),by
        }
    }' "$@" 2>/dev/null)
fi
if [ -n "$_history_html" ]; then
    printf '<table><tr><th>When</th><th>Decision</th><th>Network</th><th>IPv4</th><th>IPv6</th><th>By</th></tr>\n'
    printf '%s\n' "$_history_html"
    printf '</table>\n'
else
    printf '<p class="dim">No history yet.</p>\n'
fi

_activity_html=""
# shellcheck disable=SC2086
set -- ${BASE_DIR}/*-join-history
if [ -f "$1" ]; then
    _activity_html=$(awk -v mac="$MAC" -v base="${BASE_DIR}/" -F'\t' '
    function h(s,  t){t=s;gsub(/&/,"\\&amp;",t);gsub(/</,"\\&lt;",t);gsub(/>/,"\\&gt;",t);gsub(/"/,"\\&quot;",t);return t}
    BEGIN{
        bcls["approved"]="approved";bcls["denied"]="denied";bcls["revoked"]="revoked"
        bcls["connected"]="connected";bcls["disconnected"]="disconnected";bcls["deleted"]="deleted"
        bcls["labelled"]="labelled"
        blbl["approved"]="Approved";blbl["denied"]="Denied";blbl["revoked"]="Revoked"
        blbl["connected"]="Connected";blbl["disconnected"]="Disconnected";blbl["deleted"]="Deleted"
        blbl["labelled"]="Labelled"
    }
    tolower($11)==tolower(mac){
        fn=FILENAME; sub(base,"",fn); sub(/-join-history$/,"",fn)
        n++;rw[n]=$2;ra[n]=$3;rm[n]=$4;ri4[n]=$5;ri6[n]=$6;rnet[n]=fn
    }
    END{
        s=(n>20)?n-19:1
        for(i=n;i>=s;i--){
            act=ra[i];tmac=rm[i];net=rnet[i]
            cls=(act in bcls)?bcls[act]:"untracked"
            lbl=(act in blbl)?blbl[act]:h(act)
            tlink=(tmac!="")?"<a href=\"/cgi-bin/device?net="h(net)"&mac="h(tmac)"\">"h(tmac)"</a>":"—"
            printf "<tr><td class=\"dim\">%s</td><td><span class=\"badge badge-%s\">%s</span></td><td>%s</td><td class=\"dim\">%s</td><td>%s</td><td>%s</td></tr>\n",\
                h(rw[i]),cls,lbl,h(net),tlink,h(ri4[i]!=""?ri4[i]:"—"),h(ri6[i]!=""?ri6[i]:"—")
        }
    }' "$@" 2>/dev/null)
fi
if [ -n "$_activity_html" ]; then
    printf '<h2>Approval activity</h2>\n'
    printf '<table><tr><th>When</th><th>Action</th><th>Network</th><th>Target MAC</th><th>Target IP</th></tr>\n'
    printf '%s\n' "$_activity_html"
    printf '</table>\n'
fi

printf '<h2 style="margin-top:2rem;color:#b71c1c">Danger zone</h2>\n'
printf '<p style="font-size:.875rem;color:#555">Removes this device completely: label, rules, approved status, and DNS entry. The device will be blocked immediately and must be re-approved if it reconnects.</p>\n'
printf '<form method="POST" action="/cgi-bin/device" onsubmit="return confirm(%s)">\n' \
    "'Remove $(_html "$_DEV_DISPLAY") from $_iface? This cannot be undone.'"
printf '<input type="hidden" name="net" value="%s"><input type="hidden" name="mac" value="%s">\n' \
    "$(_html "$NET")" "$(_html "$MAC")"
printf '<input type="hidden" name="action" value="delete">\n'
printf '<button type="submit" style="background:#b71c1c;color:#fff;border:none;padding:.6rem 1.25rem;border-radius:6px;cursor:pointer;font-size:.9rem">Remove device</button>\n'
printf '</form>\n'
printf '</body></html>\n'
