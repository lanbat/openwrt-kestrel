#!/bin/bash
# test/qemu/deploy.sh — cross-build kestreld + nft-resolve, copy the repo into
# the VM, and run install.sh for real against a given network config.
#
# Usage:
#   test/qemu/deploy.sh networks/configs/guest.conf [networks/configs/untrusted.conf ...]
#
# Re-run any time you change Rust code or a config file — it's idempotent.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <config-file> [<config-file> ...]"
    echo "  e.g.  $0 networks/configs/guest.conf"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
TARGET=x86_64-unknown-linux-musl
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1"
SCP="scp -O -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2222"

echo "==> Cross-building kestreld + nft-resolve for ${TARGET}..."
( cd "$REPO_ROOT" && cross build --release --target "$TARGET" \
    --manifest-path networks/kestreld-rs/Cargo.toml )
( cd "$REPO_ROOT" && cross build --release --target "$TARGET" \
    --manifest-path split-routing/nft-resolve-rs/Cargo.toml )

echo "==> Packaging networks/ + split-routing/ (excluding target/)..."
STAGE="${WORK_DIR}/deploy-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/openwrt-kestrel"
for dir in networks split-routing; do
    rsync -a --exclude 'target' --exclude '.git' "${REPO_ROOT}/${dir}" "${STAGE}/openwrt-kestrel/"
done
tar -czf "${WORK_DIR}/deploy.tar.gz" -C "$STAGE" openwrt-kestrel

echo "==> Copying into the VM..."
$SCP "${WORK_DIR}/deploy.tar.gz" root@127.0.0.1:/tmp/
$SCP "${REPO_ROOT}/networks/kestreld-rs/target/${TARGET}/release/kestreld" \
     "${REPO_ROOT}/split-routing/nft-resolve-rs/target/${TARGET}/release/nft-resolve" \
     root@127.0.0.1:/tmp/

$SSH "
    rm -rf /root/openwrt-kestrel
    tar -xzf /tmp/deploy.tar.gz -C /root
    cp /tmp/kestreld /usr/bin/kestreld
    cp /tmp/nft-resolve /usr/bin/nft-resolve
    chmod 0755 /usr/bin/kestreld /usr/bin/nft-resolve
"

echo "==> Wiring up uhttpd CGI (matches the real router's packaged deployment)..."
$SSH "
    mkdir -p /www/cgi-bin
    for ep in status device network identity qr approve-access approve-join rotate-password plugin_info; do
        ln -sf /usr/bin/kestreld /www/cgi-bin/\$ep
    done
    if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
        uci set uhttpd.main.cgi_prefix=/cgi-bin
        uci commit uhttpd
        /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
    fi
"

for conf in "$@"; do
    name="$(basename "$conf")"
    echo "==> Copying ${name} and running install.sh..."
    $SCP "${REPO_ROOT}/${conf}" root@127.0.0.1:/root/openwrt-kestrel/networks/configs/
    $SSH "cd /root/openwrt-kestrel && sh networks/install.sh networks/configs/${name}"
done

echo "==> Verifying hostapd is actually beaconing (not just 'up')..."
sleep 3
ifaces="$($SSH "iw dev | awk '/Interface/{print \$2}'")"
any_tx=0
for ifn in $ifaces; do
    tx1="$($SSH "cat /sys/class/net/${ifn}/statistics/tx_packets 2>/dev/null || echo 0")"
    sleep 2
    tx2="$($SSH "cat /sys/class/net/${ifn}/statistics/tx_packets 2>/dev/null || echo 0")"
    if [ "$tx2" -gt "$tx1" ]; then
        echo "    OK — ${ifn} TX packets climbing (${tx1} -> ${tx2})."
        any_tx=1
    else
        echo "    ${ifn}: TX packets not increasing (${tx1} -> ${tx2}) — might just be idle, or hostapd failed silently."
    fi
done
if [ "$any_tx" -eq 0 ] && [ -n "$ifaces" ]; then
    echo "    None of the wireless interfaces are transmitting. Check:"
    echo "      ssh -p 2222 root@127.0.0.1 logread | grep -i hostapd"
fi

echo
echo "==> Done. Dashboard: http://127.0.0.1:8080/cgi-bin/status"
echo "    (SSH in with: ssh -p 2222 root@127.0.0.1 — blank password)"
