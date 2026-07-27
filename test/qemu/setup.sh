#!/bin/bash
# test/qemu/setup.sh — download (if needed) and boot a real OpenWrt VM under
# QEMU/KVM with mac80211_hwsim virtual radios, so hostapd/fw4/dnsmasq/kestreld
# all run for real. This lets you test extra-networks/split-routing changes
# before pushing them to your actual router.
#
# Usage:
#   test/qemu/setup.sh [--fresh]
#
#   --fresh   discard the current disk and boot a clean copy of the base image
#             (the downloaded base image itself is cached either way)
#
# Once booted:
#   ssh -p 2222 root@127.0.0.1                  (blank password)
#   open http://127.0.0.1:8080/cgi-bin/status    (once test/qemu/deploy.sh has run)
#
# Requires: qemu-system-x86_64, KVM (/dev/kvm), internet access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
IMG_NAME="openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img"
IMG_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/${IMG_NAME}.gz"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ "${1:-}" = "--fresh" ]; then
    rm -f disk.img qemu.pid serial.log qmon.sock
fi

if [ ! -f "${IMG_NAME}.gz" ]; then
    echo "==> Downloading OpenWrt ${OPENWRT_VERSION} (x86-64 generic)..."
    curl -# -o "${IMG_NAME}.gz" "$IMG_URL"
fi

if [ ! -f disk.img ]; then
    echo "==> Extracting base image..."
    gunzip -k -c "${IMG_NAME}.gz" > disk.img
fi

if [ -f qemu.pid ] && kill -0 "$(cat qemu.pid)" 2>/dev/null; then
    echo "==> QEMU is already running (pid $(cat qemu.pid))."
    exit 0
fi

rm -f serial.log qmon.sock

# NOTE on `ulimit -l 0`: some sandboxed/containerized environments cap
# RLIMIT_MEMLOCK very low (Docker's classic default is 8MB). QEMU 11's
# io_uring-based event-loop backend (fdmon-io_uring) asks the kernel to pin
# memory for its ring buffer; if that first pin attempt happens to succeed but
# a *later* one (a second AioContext) fails, QEMU treats that as a fatal error
# instead of falling back to epoll. Forcing the ring allocation to fail from
# the very first attempt (by making the locked-memory budget 0) makes QEMU
# take the graceful epoll fallback path every time instead. Harmless on
# systems with a normal/unlimited memlock limit.
echo "==> Booting OpenWrt under QEMU..."
(
  ulimit -l 0
  qemu-system-x86_64 \
    -enable-kvm -m 512 -smp 2 \
    -drive file=disk.img,format=raw,if=virtio,aio=threads,cache=writeback \
    -netdev user,id=lan0,net=192.168.1.0/24,hostfwd=tcp::2222-192.168.1.1:22,hostfwd=tcp::8080-192.168.1.1:80 \
    -device virtio-net-pci,netdev=lan0 \
    -netdev user,id=wan0 \
    -device virtio-net-pci,netdev=wan0 \
    -display none -serial file:serial.log -monitor unix:qmon.sock,server,nowait \
    -daemonize -pidfile qemu.pid
)
# NOTE: the LAN netdev must be attached FIRST on the command line. OpenWrt's
# stock config maps the "lan" role to eth0 by PCI/device enumeration order,
# not by the QEMU -netdev id string — attach WAN first and LAN silently ends
# up on the wrong subnet.
# NOTE: in QEMU's hostfwd syntax the *guest* address goes AFTER the dash
# (`tcp::HOSTPORT-GUESTADDR:GUESTPORT`), not before it.

echo -n "==> Waiting for SSH"
tries=0
until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
      -p 2222 root@127.0.0.1 true 2>/dev/null; do
    echo -n "."
    sleep 2
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
        echo
        echo "Timed out waiting for SSH. Check ${WORK_DIR}/serial.log for boot output."
        exit 1
    fi
done
echo " up."

echo "==> Configuring WAN (the stock image ships no default WAN interface)..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1 "
    if ! uci -q get network.wan >/dev/null 2>&1; then
        uci set network.wan=interface
        uci set network.wan.device='eth1'
        uci set network.wan.proto='dhcp'
        uci commit network
        /etc/init.d/network reload
    fi
"

echo "==> Ready. Next: test/qemu/provision.sh"
