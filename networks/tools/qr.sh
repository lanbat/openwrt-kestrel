#!/bin/sh
# Print a WiFi QR code to the terminal for a configured network.
# Guests scan it with their phone camera — no typing needed.
#
# Usage: sh qr.sh <config-file>
#
# Requires: qrencode (apk add qrencode)

set -eu

[ $# -eq 1 ] || { echo "Usage: sh qr.sh <config-file>"; exit 1; }

CONFIG="$1"
[ -f "$CONFIG" ] || { echo "ERROR: config not found: $CONFIG"; exit 1; }
. "$CONFIG"

[ -z "${SSID:-}"     ] && { echo "ERROR: SSID not set";     exit 1; }
[ -z "${WIFI_KEY:-}" ] && { echo "ERROR: WIFI_KEY not set"; exit 1; }

# Map encryption to QR type field.
case "${ENCRYPTION:-psk2}" in
    sae)         QR_TYPE=SAE ;;
    sae-mixed)   QR_TYPE=SAE ;;
    psk*|wpa*)   QR_TYPE=WPA ;;
    none|open)   QR_TYPE=nopass ;;
    *)           QR_TYPE=WPA ;;
esac

# Escape special characters in SSID and password for QR format.
_escape() { echo "$1" | sed 's/[\\;,":]/\\&/g'; }
SSID_ESC=$(_escape "$SSID")
KEY_ESC=$(_escape "$WIFI_KEY")

QR_STRING="WIFI:T:${QR_TYPE};S:${SSID_ESC};P:${KEY_ESC};;"

printf '\n  Network:  %s\n' "$SSID"
printf '  Password: %s\n'   "$WIFI_KEY"
printf '  Security: %s\n\n' "${ENCRYPTION:-psk2}"

if command -v qrencode >/dev/null 2>&1; then
    qrencode -t UTF8 -m 2 "$QR_STRING"
else
    echo "  Install qrencode for QR output:  apk add qrencode"
    echo ""
    echo "  Or scan this string with a QR generator app:"
    echo "  $QR_STRING"
fi
