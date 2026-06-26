#!/bin/sh
# Forward a port from an isolated network to a LAN host.
# Useful for temporary access — e.g. gaming with a guest.
#
# Usage: sh expose-port.sh <src-zone> <port> <dest-ip> [duration] [proto] [name]
#
#   duration  optional — auto-remove after this time: 30m, 2h, 90m (blank = permanent)
#   proto     tcp, udp, or "tcp udp" (default: tcp udp)
#   name      label for the rule — used to remove it (default: expose-<zone>-<port>)
#
# Examples:
#   sh expose-port.sh guest 27015 192.168.1.50
#   sh expose-port.sh guest 27015 192.168.1.50 2h
#   sh expose-port.sh guest 25565 192.168.1.50 3h tcp minecraft

set -eu

[ $# -lt 3 ] && {
    echo "Usage: sh expose-port.sh <src-zone> <port> <dest-ip> [duration] [proto] [name]"
    exit 1
}

ZONE="$1"
PORT="$2"
DEST="$3"
DURATION="${4:-}"
PROTO="${5:-tcp udp}"
NAME="${6:-expose-${ZONE}-${PORT}}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── duration parsing ───────────────────────────────────────────────────────────

_secs=0
if [ -n "$DURATION" ]; then
    case "$DURATION" in
        *h*m) _h=${DURATION%%h*}; _m=${DURATION##*h}; _m=${_m%m}
              _secs=$(( _h * 3600 + _m * 60 )) ;;
        *h)   _secs=$(( ${DURATION%h} * 3600 )) ;;
        *m)   _secs=$(( ${DURATION%m} * 60 )) ;;
        *)    echo "ERROR: duration format: 2h, 30m, or 1h30m"; exit 1 ;;
    esac
fi

# ── duplicate check ────────────────────────────────────────────────────────────

for s in $(uci show firewall | grep '=redirect' | cut -d. -f2 | cut -d= -f1); do
    n=$(uci -q get firewall."$s".name 2>/dev/null || true)
    [ "$n" = "$NAME" ] && {
        echo "ERROR: rule '$NAME' already exists — run unexpose-port.sh $NAME first"
        exit 1
    }
done

# ── add firewall redirect ──────────────────────────────────────────────────────

uci add firewall redirect >/dev/null
uci set firewall.@redirect[-1].name="$NAME"
uci set firewall.@redirect[-1].src="$ZONE"
uci set firewall.@redirect[-1].src_dport="$PORT"
uci set firewall.@redirect[-1].dest=lan
uci set firewall.@redirect[-1].dest_ip="$DEST"
uci set firewall.@redirect[-1].dest_port="$PORT"
uci set firewall.@redirect[-1].proto="$PROTO"
uci set firewall.@redirect[-1].target=DNAT
uci commit firewall
fw4 reload >/dev/null

# ── schedule removal ───────────────────────────────────────────────────────────

if [ "$_secs" -gt 0 ]; then
    _exp=$(( $(date +%s) + _secs ))

    # Format expiry as cron fields — try date -d @epoch (busybox), fall back to arithmetic.
    _exp_str=$(date -d "@$_exp" '+%M %H %d %m' 2>/dev/null) || {
        _h=$(date +%H); _h=$(( 10#$_h ))
        _m=$(date +%M); _m=$(( 10#$_m ))
        _tot_m=$(( _h * 60 + _m + _secs / 60 ))
        _exp_h=$(( (_tot_m / 60) % 24 ))
        _exp_m=$(( _tot_m % 60 ))
        # Day rollover: increment day if hours wrapped.
        if [ $(( _tot_m / 60 )) -ge 24 ]; then
            _exp_day=$(date +%-d 2>/dev/null || date +%d | sed 's/^0//')
            _exp_day=$(( _exp_day + 1 ))
        else
            _exp_day=$(date +%d)
        fi
        _exp_str="$(printf '%02d' $_exp_m) $(printf '%02d' $_exp_h) $_exp_day $(date +%m)"
    }

    read -r _cmin _chour _cday _cmon <<EOF
$_exp_str
EOF

    CRON_LINE="$_cmin $_chour $_cday $_cmon * sh $SCRIPT_DIR/unexpose-port.sh $NAME  # $NAME"
    ( crontab -l 2>/dev/null | grep -v "# $NAME"; echo "$CRON_LINE" ) | crontab -

    _exp_human=$(date -d "@$_exp" '+%H:%M on %d/%m' 2>/dev/null \
                 || printf '%02d:%02d' "$_chour" "$_cmin")
    echo "Auto-remove: $_exp_human (cron)"
fi

# ── summary ───────────────────────────────────────────────────────────────────

ZONE_IP=$(ip addr show br-"$ZONE" 2>/dev/null \
          | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
echo "Exposed:     $ZONE clients → ${ZONE_IP}:${PORT} → ${DEST}:${PORT} ($PROTO)"
[ "$_secs" -eq 0 ] && echo "Duration:    permanent — remove with: sh unexpose-port.sh $NAME"
