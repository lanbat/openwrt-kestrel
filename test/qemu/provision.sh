#!/bin/bash
# test/qemu/provision.sh — install mac80211_hwsim + hostapd + wpa_supplicant
# inside the VM booted by setup.sh, and fix the one config issue that silently
# prevents hostapd from ever starting (see README.md "Known gotchas").
#
# Usage:
#   test/qemu/provision.sh [country-code]     (default: US)
#
# Safe to re-run.
set -euo pipefail

COUNTRY="${1:-US}"
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1"

echo "==> Installing packages (hwsim, hostapd, wpa_supplicant, iw, qrencode)..."
$SSH "apk update >/dev/null && apk add kmod-mac80211-hwsim hostapd-mbedtls wpa-supplicant iw qrencode 2>&1 | tail -5"

# mac80211_hwsim defaults to 2 radios: one AP (radio0 — guest and untrusted
# already share it as two BSSes, same as a real router with one radio card
# and multiple SSIDs) and one simulated client (radio1). That's only ever
# enough for one simulated device at a time, though — bump it to 4 so
# test/qemu/client.sh can bring up to three independent client stations
# concurrently (radio1/2/3), e.g. one device joining guest and another
# joining untrusted in the same test run, or two devices for an
# ambiguous-fingerprint-match scenario. This only takes effect on module
# (re)load, and OpenWrt's board-detect only populates uci wireless.radioN
# sections for
# phys that exist *when it runs* (at boot) — so a reboot, not just a module
# reload, is the reliable way to pick this up with the uci config generated
# for us instead of hand-writing wireless.radio2/radio3 from scratch.
current_radios="$($SSH "cat /sys/module/mac80211_hwsim/parameters/radios 2>/dev/null || echo 0")"
if [ "$current_radios" != "4" ]; then
    echo "==> Bumping mac80211_hwsim from ${current_radios} to 4 radios (1 AP + 3 client stations)..."
    $SSH "echo 'mac80211_hwsim radios=4' > /etc/modules.d/mac80211-hwsim"
    echo "==> Rebooting to apply it (module options only take effect on load)..."
    $SSH "reboot" >/dev/null 2>&1 || true
    echo -n "==> Waiting for the VM to come back"
    tries=0
    until $SSH true 2>/dev/null; do
        echo -n "."
        sleep 3
        tries=$((tries + 1))
        if [ "$tries" -gt 40 ]; then
            echo
            echo "Timed out waiting for the VM to reboot."
            exit 1
        fi
    done
    echo " back."
fi

echo "==> Configuring radio0-radio3 (band/channel/country)..."
# radio0 is the sole AP radio (guest + untrusted run as two BSSes on it,
# via install.sh's normal multi-network support — see test/qemu/configs/
# untrusted.conf). radio1/radio2/radio3 are three independent client
# stations for test/qemu/client.sh, left disabled at the netifd/AP level so
# each is purely client-managed; distinct bands/channels are just for
# hygiene; hwsim clients associate on whatever channel the AP they join is
# actually using, so this isn't functionally required without wmediumd.
#
# NOTE: the auto-detected wireless config sets `option country '00'` on every
# radio. hostapd flatly rejects country_code '00' and fails to start the BSS
# --- but it fails *silently* from the outside: `iw dev` still shows the
# interface as type AP, ubus still reports it "up", and nothing looks wrong
# until you check /sys/class/net/<if>/statistics/tx_packets and see it's
# stuck at 0 (no beacons ever sent). Every radio needs a real country code,
# not just the one you're using, because `iw reg set` is a *global* kernel
# call — any radio still at '00' silently resets the regdomain right back
# after another radio's setup runs.
$SSH "
    uci set wireless.radio0.band='2g'
    uci set wireless.radio0.channel='1'
    uci set wireless.radio0.htmode='HT20'
    uci set wireless.radio0.country='${COUNTRY}'
    uci set wireless.radio0.disabled='0'
    uci set wireless.radio1.band='5g'
    uci set wireless.radio1.channel='36'
    uci set wireless.radio1.htmode='HT20'
    uci set wireless.radio1.country='${COUNTRY}'
    uci set wireless.radio1.disabled='1'
    uci set wireless.radio2.band='5g'
    uci set wireless.radio2.channel='149'
    uci set wireless.radio2.htmode='HT20'
    uci set wireless.radio2.country='${COUNTRY}'
    uci set wireless.radio2.disabled='1'
    uci set wireless.radio3.band='2g'
    uci set wireless.radio3.channel='11'
    uci set wireless.radio3.htmode='HT20'
    uci set wireless.radio3.country='${COUNTRY}'
    uci set wireless.radio3.disabled='1'
    uci -q delete wireless.default_radio1 2>/dev/null || true
    uci -q delete wireless.default_radio2 2>/dev/null || true
    uci -q delete wireless.default_radio3 2>/dev/null || true
    uci commit wireless
"

echo "==> Restarting networking to apply it..."
# A plain `wifi up`/`wifi reload`/`ubus call network.wireless up` is NOT
# enough here — the wifi-device-level config (including country) appears to
# be cached at netifd-process lifetime and only gets re-read on a full
# network restart. This briefly drops br-lan (and this SSH session) for
# ~15-20s; that's expected, not a failure.
$SSH "/etc/init.d/network restart" >/dev/null 2>&1 || true

echo -n "==> Waiting for it to come back"
tries=0
until $SSH true 2>/dev/null; do
    echo -n "."
    sleep 2
    tries=$((tries + 1))
    if [ "$tries" -gt 30 ]; then
        echo
        echo "Timed out waiting for the VM to come back after network restart."
        exit 1
    fi
done
echo " back."

echo "==> Provisioned (no AP configured yet — that happens via deploy.sh + install.sh)."
echo "    Next: test/qemu/deploy.sh test/qemu/configs/guest.conf test/qemu/configs/untrusted.conf"
