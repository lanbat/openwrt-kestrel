#!/bin/sh
# Generate a new WiFi password for a network and apply it immediately.
#
# Usage: sh rotate-password.sh <config-file>
#
# Updates the config file in place and reloads wireless. The new password is
# shown as text and (if qrencode is installed) as a QR code.

set -eu

[ $# -eq 1 ] || { echo "Usage: sh rotate-password.sh <config-file>"; exit 1; }

CONFIG="$1"
[ -f "$CONFIG" ] || { echo "ERROR: config not found: $CONFIG"; exit 1; }
. "$CONFIG"

[ -z "${IFACE:-}" ] && { echo "ERROR: IFACE not set"; exit 1; }

WIFI_UCI="${WIFI_UCI:-$IFACE}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. /etc/extra-networks/_lib.sh

NEW_KEY=$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 20)

# Update config file
if grep -q '^WIFI_KEY=' "$CONFIG"; then
    sed -i "s|^WIFI_KEY=.*|WIFI_KEY=$NEW_KEY|" "$CONFIG"
else
    printf 'WIFI_KEY=%s\n' "$NEW_KEY" >>"$CONFIG"
fi

# Update UCI for primary and extra radio sections
uci set wireless."$WIFI_UCI".key="$NEW_KEY"
[ -n "${RADIO_EXTRA:-}" ] && uci -q get wireless."${WIFI_UCI}_extra" >/dev/null 2>&1 \
    && uci set wireless."${WIFI_UCI}_extra".key="$NEW_KEY"
uci commit wireless

# Clear join approvals — everyone re-connects with the new password and needs re-approval
rm -f "/etc/extra-networks/${IFACE}-join-approved" "/etc/extra-networks/${IFACE}-join-pending"

wifi reload

printf '\nPassword rotated: %s (%s)\n' "$IFACE" "${SSID:-$IFACE}"
printf 'New password:     %s\n\n' "$NEW_KEY"

# Print QR code using the updated config
WIFI_KEY="$NEW_KEY"
sh "$SCRIPT_DIR/qr.sh" "$CONFIG"

# Regenerate the web QR page so the notification link is current
_qr_url=""
if [ -f "$SCRIPT_DIR/guest-info.sh" ] && sh "$SCRIPT_DIR/guest-info.sh" "$CONFIG" >/dev/null 2>&1; then
    _rip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
    _qr_url="http://${_rip:-192.168.1.1}/net/${IFACE}.html"
fi

_load_notify "$IFACE"
_ntfy "Password rotated — ${SSID:-$IFACE}" default key \
"Type: Password rotated

New password: ${NEW_KEY}${_qr_url:+
QR code: ${_qr_url}}" \
    "${_qr_url:+view, QR code, ${_qr_url}}"
