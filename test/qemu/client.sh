#!/bin/bash
# test/qemu/client.sh — simulate a WiFi client connecting to one of the
# networks set up by deploy.sh, using one of the hwsim client radios
# (radio1/radio2/radio3, see provision.sh) as a station. Real 802.11
# association + real DHCP, not a mock.
#
# Usage:
#   test/qemu/client.sh <ssid> <psk> [mac-address] [phy]
#
#   test/qemu/client.sh hwsim-test-guest testpassword123
#   test/qemu/client.sh hwsim-test-guest testpassword123 aa:bb:cc:dd:ee:01
#   test/qemu/client.sh hwsim-test-untrusted testpassword456 "" phy2
#
# phy defaults to phy1. Pass phy2 or phy3 to run additional simulated
# clients *concurrently* with this one — each phy gets its own station
# interface and its own wpa_supplicant/pidfile, so running client.sh
# multiple times with different phys (e.g. one joining guest, another
# joining untrusted) doesn't tear down an already-connected client.
#
# Prints the DHCP-assigned IP on success. Re-run with the same phy to
# simulate a different device on it (pass a different MAC) or reconnect the
# same one.
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <ssid> <psk> [mac-address] [phy]"
    exit 1
fi
SSID="$1"
PSK="$2"
MAC="${3:-}"
PHY="${4:-phy1}"
IFNAME="sta-${PHY}"

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1"

echo "==> Bringing up a fresh station interface on ${PHY} (${IFNAME})..."
$SSH "
    [ -f /tmp/wpa_${IFNAME}.pid ] && kill -9 \$(cat /tmp/wpa_${IFNAME}.pid) 2>/dev/null
    rm -f /tmp/wpa_${IFNAME}.pid /var/run/wpa_supplicant/${IFNAME}
    iw dev ${IFNAME} del 2>/dev/null || true
    iw phy ${PHY} interface add ${IFNAME} type managed
    $( [ -n "$MAC" ] && echo "ip link set ${IFNAME} address ${MAC}" )
    ip link set ${IFNAME} up
"

echo "==> Associating to '${SSID}'..."
$SSH "
    cat > /tmp/wpa_${IFNAME}.conf << EOF
ctrl_interface=/var/run/wpa_supplicant
country=US
network={
    ssid=\"${SSID}\"
    key_mgmt=WPA-PSK
    psk=\"${PSK}\"
}
EOF
    wpa_supplicant -B -i ${IFNAME} -c /tmp/wpa_${IFNAME}.conf -D nl80211 -P /tmp/wpa_${IFNAME}.pid >/tmp/wpa_${IFNAME}.log 2>&1
"

echo -n "==> Waiting for association"
tries=0
until $SSH "iw dev ${IFNAME} link | grep -q Connected" 2>/dev/null; do
    echo -n "."
    sleep 1
    tries=$((tries + 1))
    if [ "$tries" -gt 15 ]; then
        echo
        echo "Never associated. Log:"
        $SSH "cat /tmp/wpa_${IFNAME}.log"
        exit 1
    fi
done
echo " connected."

echo "==> Requesting a DHCP lease..."
# Captured into a variable rather than piped straight into `grep -q` —
# `-q` exits on the first match without draining the rest of its input,
# and under `pipefail` the resulting SIGPIPE to the ssh/tee stages upstream
# reads as a spurious pipeline failure even though the lease was obtained.
lease_output="$($SSH "udhcpc -i ${IFNAME} -n -q" 2>&1)" || true
echo "$lease_output"
if [[ "$lease_output" != *obtained* ]]; then
    echo
    echo "No lease obtained — if this network has ALLOWLIST=yes, the MAC needs"
    echo "to be added to <iface>-allowed-macs first (or set one with -m/[mac-address] and add it)."
    exit 1
fi

IP="$($SSH "ip -4 addr show ${IFNAME} | awk '/inet /{print \$2}' | cut -d/ -f1")"
echo
echo "==> Connected. IP: ${IP}"
echo "    Check the dashboard: http://127.0.0.1:8080/cgi-bin/status"
echo "    Approve it:          curl (or open the link in the dashboard's device row)"
