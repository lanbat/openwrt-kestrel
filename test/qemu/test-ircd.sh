#!/bin/bash
# test/qemu/test-ircd.sh — enable and smoke-test the LAN-only sf-ircd service
# against the running OpenWrt VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1)
LOCAL_PORT=16697
CERT_DER="${WORK_DIR}/sf-ircd-qemu.crt.der"
CERT_PEM="${WORK_DIR}/sf-ircd-qemu.crt.pem"
PROTOCOL_OUTPUT="${WORK_DIR}/sf-ircd-protocol.txt"

cleanup() {
    if [ -n "${TUNNEL_PID:-}" ]; then
        kill "$TUNNEL_PID" 2>/dev/null || true
        wait "$TUNNEL_PID" 2>/dev/null || true
    fi
    rm -f "$CERT_DER" "$CERT_PEM" "$PROTOCOL_OUTPUT"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"

echo "==> Enabling sf-ircd on the trusted LAN address..."
"${SSH[@]}" '
    uci set sf-ircd.main.enabled=1
    uci set sf-ircd.main.listen_addr=192.168.1.1:6697
    uci commit sf-ircd
    /etc/init.d/sf-ircd restart
    sleep 2
    /etc/init.d/sf-ircd status
'

echo "==> Checking listener and LAN-only firewall rule..."
"${SSH[@]}" '
    netstat -lntp | grep -F "192.168.1.1:6697"
    nft list chain inet fw4 input_lan | grep -F "dport 6697"
    if nft list ruleset | grep -E "input_(guest|untrusted).*6697"; then
        echo "IRC port unexpectedly exposed to another zone" >&2
        exit 1
    fi
'

echo "==> Checking TLS with the router's configured certificate..."
"${SSH[@]}" 'cat /etc/uhttpd.crt' >"$CERT_DER"
openssl x509 -inform DER -in "$CERT_DER" -out "$CERT_PEM"
ssh -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -p 2222 \
    -L "${LOCAL_PORT}:192.168.1.1:6697" root@127.0.0.1 \
    >/tmp/sf-ircd-qemu-tunnel.log 2>&1 &
TUNNEL_PID=$!
sleep 2
openssl s_client -brief -verify_return_error -CAfile "$CERT_PEM" \
    -connect "127.0.0.1:${LOCAL_PORT}" -servername OpenWrt </dev/null 2>&1 \
    | grep -F "Protocol version: TLSv1.3"

echo "==> Checking IRCv3 CAP and PING exchange..."
printf 'CAP LS 302\nNICK smoke\nUSER smoke 0 * :Smoke Test\nPRIVMSG #sf-smoke :/sf groups\nPING :smoke\nQUIT\n' \
    | timeout 5 openssl s_client -quiet -verify_return_error -CAfile "$CERT_PEM" \
        -connect "127.0.0.1:${LOCAL_PORT}" -servername OpenWrt \
        >"$PROTOCOL_OUTPUT" 2>&1 || true
grep -F " CAP * LS :message-tags server-time" "$PROTOCOL_OUTPUT"
grep -F " PONG :smoke" "$PROTOCOL_OUTPUT"
grep -F " 001 smoke " "$PROTOCOL_OUTPUT"
grep -F " NOTICE smoke :[sf] " "$PROTOCOL_OUTPUT"

echo "sf-ircd QEMU smoke test passed."
