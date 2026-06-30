#!/bin/sh
# Send a daily traffic digest for all isolated networks.
# Installed as a daily cron entry by install.sh when NOTIFY_URL is set.

BASE_DIR=/etc/extra-networks

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

_router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
_dashboard_url="http://${_router_ip:-192.168.1.1}/cgi-bin/status"

hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo router)

# ── Google Calendar: events tomorrow ──────────────────────────────────────────

_cal_section=""
unset GCAL_URL GCAL_TZ_OFFSET
[ -f "${BASE_DIR}/config" ] && . "${BASE_DIR}/config"

if [ -n "${GCAL_URL:-}" ]; then
    _ics=$(curl -sf --max-time 15 "$GCAL_URL" 2>/dev/null)
    if [ -n "$_ics" ]; then
        _events=$(printf '%s\n' "$_ics" | tr -d '\r' | \
            awk '{if(substr($0,1,1)==" "){printf "%s",substr($0,2)}else{if(NR>1)printf "\n";printf "%s",$0}}END{printf "\n"}' | \
            awk -v now="$(date +%s)" -v tz="${GCAL_TZ_OFFSET:-0}" '
            BEGIN {
                for (i=1; i<=7; i++) {
                    ts = now + i*86400
                    dmap[strftime("%Y%m%d",ts)] = strftime("%a %d %b",ts)
                }
            }
            function tparts(dt,   h,m) {
                if (length(dt) < 13) return "0000\tall day"
                h = substr(dt,10,2)+0; m = substr(dt,12,2)+0
                if (substr(dt,length(dt),1)=="Z") {
                    h = h + tz
                    if (h >= 24) h = h - 24
                    if (h < 0)  h = h + 24
                }
                return sprintf("%02d%02d\t%02d:%02d",h,m,h,m)
            }
            /^BEGIN:VEVENT/ { ev=1; dt=""; sm="" }
            /^END:VEVENT/   {
                if (ev && sm!="") {
                    dpart = substr(dt,1,8)
                    if (dpart in dmap) {
                        split(tparts(dt),tp,"\t")
                        print dpart "T" tp[1] "\t" dmap[dpart] " — " sm " (" tp[2] ")"
                    }
                }
                ev=0
            }
            ev && /^DTSTART/  { n=split($0,a,":"); dt=a[n]; gsub(/[^0-9TZ]/,"",dt) }
            ev && /^SUMMARY:/ { sm=substr($0,9); gsub(/\\,/,",",sm); gsub(/\\n/," ",sm) }
            ' | sort | awk -F'\t' '{print $2}')
        if [ -n "$_events" ]; then
            _cal_section=$(printf '\n\nUpcoming events:\n%s' \
                "$(printf '%s\n' "$_events" | awk '{print "• "$0}')")
        fi
    fi
fi

# VPN status line
VPN_CFG=/etc/split-routing/config
_vpn_line=""
if [ -f "$VPN_CFG" ]; then
    unset VPN_IFACE ROUTE_TABLE FWMARK NOTIFY_URL
    . "$VPN_CFG"
    _if_up=no; ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" && _if_up=yes
    _rule=no;  ip rule show 2>/dev/null | grep -q "lookup ${ROUTE_TABLE}" && _rule=yes
    _rt=no;    ip route show table "$ROUTE_TABLE" 2>/dev/null | grep -q "^default" && _rt=yes
    if [ "$_if_up$_rule$_rt" = yesyesyes ]; then
        _vpn_line="VPN (${VPN_IFACE}): up"
    else
        _vpn_line="VPN (${VPN_IFACE}): DOWN"
    fi
fi

seen_urls=""
for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB
    . "$_conf"
    [ -z "${NOTIFY_URL:-}" ] && continue

    _iface="$IFACE_NAME"
    [ -z "$_iface" ] && continue

    _rx=$(_nft_bytes "${_iface}_counter" in)
    _tx=$(_nft_bytes "${_iface}_counter" out)
    _dc=$(awk -v s="${SUBNET}." '$3~s{c++} END{print c+0}' /tmp/dhcp.leases 2>/dev/null)
    _rules=$(uci show firewall 2>/dev/null \
        | grep -c "^firewall\.allow_lan_${_iface}" || echo 0)

    _dc_str=$([ "${_dc:-0}" = 1 ] && echo "1 device" || echo "${_dc:-0} devices")
    _rules_str=$([ "${_rules:-0}" = 1 ] && echo "1 LAN rule" || echo "${_rules:-0} LAN rules")

    _body="${_vpn_line:+${_vpn_line}

}${_iface} — ${_dc_str}
  ↓ $(_human "$_rx")  ↑ $(_human "$_tx")
  ${_rules_str}${_cal_section}

Dashboard: ${_dashboard_url}"

    case " $seen_urls " in *" $NOTIFY_URL "*) ;;
    *)
        seen_urls="$seen_urls $NOTIFY_URL"
        curl -sf -X POST "$NOTIFY_URL" \
            -H "Title: Daily digest — ${hostname}" \
            -H "Priority: low" \
            -H "Tags: bar_chart" \
            -H "Actions: view, Dashboard, ${_dashboard_url}" \
            -d "$_body" >/dev/null &
        ;;
    esac
done
