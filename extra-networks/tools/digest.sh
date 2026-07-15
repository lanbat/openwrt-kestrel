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

# ── System health ─────────────────────────────────────────────────────────────

_up=$(awk '{print $1}' /proc/uptime 2>/dev/null)
_up_str=$(awk -v s="${_up:-0}" 'BEGIN{
    d=int(s/86400); h=int((s%86400)/3600)
    if(d>0) printf "%d day%s %d hour%s",d,(d!=1?"s":""),h,(h!=1?"s":"")
    else    printf "%d hour%s",h,(h!=1?"s":"")
}')
_mem_pct=$(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{printf "%.0f",(t-a)*100/t}' \
           /proc/meminfo 2>/dev/null)
_sys_line="Router up ${_up_str}, memory ${_mem_pct:-?}% used"

# ── Google Calendar: events in next 7 days ────────────────────────────────────

_cal_top=""
unset GCAL_URL GCAL_TZ_OFFSET
[ -f "${BASE_DIR}/config" ] && . "${BASE_DIR}/config"

if [ -n "${GCAL_URL:-}" ]; then
    _ics=$(curl -sf --max-time 15 "$GCAL_URL" 2>/dev/null)
    if [ -n "$_ics" ]; then
        _events=$(printf '%s\n' "$_ics" | tr -d '\r' | \
            awk '{if(substr($0,1,1)==" "){printf "%s",substr($0,2)}else{if(NR>1)printf "\n";printf "%s",$0}}END{printf "\n"}' | \
            awk -v now="$(date +%s)" -v tz="${GCAL_TZ_OFFSET:-0}" '
            BEGIN {
                win_start = now + 86400
                win_end   = now + 7*86400 + 86399
                for (i=1; i<=7; i++) {
                    ts = now + i*86400
                    dmap[strftime("%Y%m%d",ts)] = strftime("%a %d %b",ts)
                }
            }
            function ymd_epoch(ymd,   y,m,d,i,leap,md,days) {
                y=substr(ymd,1,4)+0; m=substr(ymd,5,2)+0; d=substr(ymd,7,2)+0
                split("31 28 31 30 31 30 31 31 30 31 30 31",md)
                days=0
                for(i=1970;i<y;i++){leap=(i%4==0&&(i%100!=0||i%400==0))+0;days+=365+leap}
                leap=(y%4==0&&(y%100!=0||y%400==0))+0; if(leap)md[2]=29
                for(i=1;i<m;i++)days+=md[i]
                return (days+d-1)*86400
            }
            function tparts(dt,   h,m) {
                if (length(dt) < 13) return "0000\tall day"
                h=substr(dt,10,2)+0; m=substr(dt,12,2)+0
                if(substr(dt,length(dt),1)=="Z"){h=h+tz;if(h>=24)h-=24;if(h<0)h+=24}
                return sprintf("%02d%02d\t%02d:%02d",h,m,h,m)
            }
            /^BEGIN:VEVENT/ { ev=1; dt=""; sm=""; rrule="" }
            /^END:VEVENT/ {
                if (ev && sm!="") {
                    dpart=substr(dt,1,8)
                    if (rrule!="") {
                        freq=""; interval=1; until=""
                        if(match(rrule,/FREQ=[A-Z]+/)){tmp=substr(rrule,RSTART,RLENGTH);sub(/FREQ=/,"",tmp);freq=tmp}
                        if(match(rrule,/INTERVAL=[0-9]+/)){tmp=substr(rrule,RSTART,RLENGTH);sub(/INTERVAL=/,"",tmp);interval=tmp+0}
                        if(match(rrule,/UNTIL=[0-9]+/)){tmp=substr(rrule,RSTART,RLENGTH);sub(/UNTIL=/,"",tmp);until=substr(tmp,1,8)}
                        if (freq=="WEEKLY") {
                            step=interval*7*86400; base=ymd_epoch(dpart)
                            win_start_day=strftime("%Y%m%d",win_start)
                            diff=win_start-base; k=(diff>0)?int(diff/step):0
                            occ=base+k*step
                            occ_day=strftime("%Y%m%d",occ)
                            if(occ_day < win_start_day){occ+=step; occ_day=strftime("%Y%m%d",occ)}
                            if(occ_day in dmap && (until=="" || occ_day<=until)){split(tparts(dt),tp,"\t");print occ_day "T" tp[1] "\t" dmap[occ_day] " — " sm " (" tp[2] ")"}
                        }
                    } else {
                        if (dpart in dmap) {
                            split(tparts(dt),tp,"\t")
                            print dpart "T" tp[1] "\t" dmap[dpart] " — " sm " (" tp[2] ")"
                        }
                    }
                }
                ev=0
            }
            ev && /^DTSTART/  { n=split($0,a,":"); dt=a[n]; gsub(/[^0-9TZ]/,"",dt) }
            ev && /^RRULE:/   { rrule=$0 }
            ev && /^SUMMARY:/ { sm=substr($0,9); gsub(/\\,/,",",sm); gsub(/\\n/," ",sm) }
            ' | sort | awk -F'\t' '{print $2}')
        if [ -n "$_events" ]; then
            _cal_top="This week:
$(printf '%s\n' "$_events" | awk '{print "• "$0}')"
        fi
    fi
fi

# ── VPN status ────────────────────────────────────────────────────────────────

_vpn_section=""
for _vpnconf in /etc/split-routing/vpn-*.conf; do
    [ -f "$_vpnconf" ] || continue
    unset VPN_IFACE ROUTE_TABLE FWMARK
    . "$_vpnconf"
    [ -n "${VPN_IFACE:-}" ] || continue
    _tier=$(basename "$_vpnconf" .conf | sed 's/^vpn-//')
    _tier_upper=$(printf '%s' "$_tier" | tr 'a-z' 'A-Z')
    _if_up=no; ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" && _if_up=yes
    _rule=no;  ip rule show 2>/dev/null | grep -q "lookup ${ROUTE_TABLE:-}" && _rule=yes
    _rt=no;    ip route show table "${ROUTE_TABLE:-}" 2>/dev/null | grep -q "^default" && _rt=yes
    [ "$_if_up$_rule$_rt" = yesyesyes ] && _st="running" || _st="offline"
    _vpn_section="${_vpn_section:+${_vpn_section}
}${_tier_upper} VPN: ${_st}"
done

# ── Routing set sizes ─────────────────────────────────────────────────────────

_sets_line=""
if [ -d /etc/split-routing ]; then
    _sets_ok=1; _sets_any=0
    for _conf in /etc/split-routing/vpn-*.conf; do
        [ -f "$_conf" ] || continue
        _tier=$(basename "$_conf" .conf | sed 's/^vpn-//')
        unset VPN_IFACE DNS_CATS RESOLVE_CATS
        . "$_conf"
        for _c in ${DNS_CATS:-}; do
            _sets_any=1
            _n=$(nft list set inet fw4 "dns_${_tier}_${_c}4" 2>/dev/null \
                 | awk '/expires/{c++}END{print c+0}')
            [ "${_n:-0}" = "0" ] && _sets_ok=0
        done
        for _c in ${RESOLVE_CATS:-}; do
            _sets_any=1
            _n=$(nft list set inet fw4 "resolve_${_tier}_${_c}4" 2>/dev/null \
                 | awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{c++}END{print c+0}')
            [ "${_n:-0}" = "0" ] && _sets_ok=0
        done
    done
    if [ "$_sets_any" = 1 ]; then
        _log_ts=$(stat -c %Y /tmp/routing-sets.log 2>/dev/null); _log_ts=${_log_ts:-0}
        _log_age=""
        if [ "${_log_ts:-0}" -gt 0 ]; then
            _age_secs=$(( $(date +%s) - _log_ts ))
            if [ "$_age_secs" -lt 3600 ]; then
                _log_age=", refreshed $(( _age_secs / 60 )) minutes ago"
            else
                _log_age=", refreshed $(( _age_secs / 3600 )) hours ago"
            fi
        fi
        if [ "$_sets_ok" = 0 ]; then
            _sets_line="Blocklists: some lists are empty${_log_age}"
        else
            _sets_line="Blocklists: up to date${_log_age}"
        fi
    fi
fi

# ── WireGuard server peer activity ────────────────────────────────────────────

_wg_section=""
for _wg_if in $(wg show interfaces 2>/dev/null); do
    _has_ep=$(wg show "$_wg_if" endpoints 2>/dev/null \
              | awk '$2!="(none)"{c++}END{print c+0}')
    [ "${_has_ep:-0}" -gt 0 ] && continue
    _now=$(date +%s); _total=0; _active=0
    while IFS=$(printf '\t') read -r _pub _pre _ep _al _hs _rx _tx _ka; do
        _total=$(( _total + 1 ))
        [ "${_hs:-0}" -gt 0 ] && [ $(( _now - _hs )) -lt 86400 ] && \
            _active=$(( _active + 1 ))
    done <<WGEOF
$(wg show "$_wg_if" dump 2>/dev/null | tail -n +2)
WGEOF
    [ "$_total" -gt 0 ] && _wg_section="${_wg_section:+${_wg_section}
}VPN server: ${_active} of ${_total} client$([ "$_total" = 1 ] || printf 's') connected today"
done

# ── Access log counts since boot ──────────────────────────────────────────────

_log_lines=$(logread 2>/dev/null)
_lan_reqs=$(printf '%s\n' "$_log_lines" | awk '/EXTNET-2LAN/{c++}END{print c+0}')
_deny=$(printf '%s\n' "$_log_lines" | awk '/EXTNET-DENY/{c++}END{print c+0}')
unset _log_lines
_activity_line=""
_activity_parts=""
[ "${_lan_reqs:-0}" -gt 0 ] && \
    _activity_parts="${_lan_reqs} access request$([ "$_lan_reqs" = 1 ] || printf 's')"
[ "${_deny:-0}" -gt 0 ] && \
    _activity_parts="${_activity_parts:+${_activity_parts}, }${_deny} device$([ "$_deny" = 1 ] || printf 's') blocked"
[ -n "$_activity_parts" ] && _activity_line="${_activity_parts} since last restart"

# ── Access rules expiring today or tomorrow ───────────────────────────────────

_today_d=$(date +%d)
_today_m=$(date +%m)
_tmrw_d=$(awk -v s="$(date +%s)" 'BEGIN{print strftime("%d",s+86400)}')
_tmrw_m=$(awk -v s="$(date +%s)" 'BEGIN{print strftime("%m",s+86400)}')
_expiry_tmp=$(mktemp)
crontab -l 2>/dev/null | grep 'allow-service.sh remove' | while IFS= read -r _cline; do
    _cmin=$(printf  '%s' "$_cline" | awk '{print $1}')
    _chour=$(printf '%s' "$_cline" | awk '{print $2}')
    _cday=$(printf  '%s' "$_cline" | awk '{printf "%02d",$3}')
    _cmon=$(printf  '%s' "$_cline" | awk '{printf "%02d",$4}')
    _rname=$(printf '%s' "$_cline" | sed 's/.*# //')
    if [ "$_cday" = "$_today_d" ] && [ "$_cmon" = "$_today_m" ]; then
        _when="today at $(printf '%02d:%02d' "$_chour" "$_cmin")"
    elif [ "$_cday" = "$_tmrw_d" ] && [ "$_cmon" = "$_tmrw_m" ]; then
        _when="tomorrow at $(printf '%02d:%02d' "$_chour" "$_cmin")"
    else
        continue
    fi
    _dst=$(uci -q get firewall."$_rname".dest_ip   2>/dev/null || echo "?")
    _port=$(uci -q get firewall."$_rname".dest_port 2>/dev/null || echo "?")
    printf '• Access for %s → port %s — %s\n' "$_dst" "$_port" "$_when"
done > "$_expiry_tmp"
_expiry_section=""
[ -s "$_expiry_tmp" ] && _expiry_section="

Expiring soon:
$(cat "$_expiry_tmp")"
rm -f "$_expiry_tmp"

# ── Collect per-network traffic and unique notify URLs ────────────────────────

_networks_section=""
_notify_urls=""
for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB DESCRIPTION
    . "$_conf"
    [ -z "${IFACE_NAME:-}" ] && continue

    _iface="$IFACE_NAME"
    _down=$(_nft_bytes "${_iface}_counter" out)
    _up=$(_nft_bytes "${_iface}_counter" in)
    _dc=$(awk -v s="${SUBNET}." '$3~s{c++} END{print c+0}' /tmp/dhcp.leases 2>/dev/null)
    _dc_str=$([ "${_dc:-0}" = 1 ] && echo "1 device" || echo "${_dc:-0} devices")
    _display="${DESCRIPTION:-$(printf '%s' "$_iface" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')}"

    _networks_section="${_networks_section:+${_networks_section}

}${_display} — ${_dc_str}
↓ $(_human "$_down")  ↑ $(_human "$_up")"

    [ -n "${NOTIFY_URL:-}" ] || continue
    case " $_notify_urls " in *" $NOTIFY_URL "*) ;; *)
        _notify_urls="${_notify_urls:+${_notify_urls} }${NOTIFY_URL}" ;;
    esac
done

# ── Send one digest per unique notify URL ─────────────────────────────────────

for _url in $_notify_urls; do
    _body="${_cal_top:+${_cal_top}

}${_sys_line}"
    [ -n "$_vpn_section" ]      && _body="${_body}

${_vpn_section}"
    [ -n "$_networks_section" ] && _body="${_body}

${_networks_section}"
    _meta=""
    [ -n "$_wg_section" ]    && _meta="${_meta:+${_meta}
}${_wg_section}"
    [ -n "$_sets_line" ]     && _meta="${_meta:+${_meta}
}${_sets_line}"
    [ -n "$_activity_line" ] && _meta="${_meta:+${_meta}
}${_activity_line}"
    [ -n "$_meta" ]          && _body="${_body}

${_meta}"
    [ -n "$_expiry_section" ] && _body="${_body}${_expiry_section}"
    _body="${_body}

Dashboard: ${_dashboard_url}"

    curl -sf -X POST "$_url" \
        -H "Title: Daily digest — ${hostname}" \
        -H "Priority: low" \
        -H "Tags: bar_chart" \
        -H "Actions: view, Dashboard, ${_dashboard_url}" \
        -d "$_body" >/dev/null &
done
