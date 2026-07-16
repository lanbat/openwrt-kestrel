# GNUmakefile — build, package, and release the openwrt-router Rust binaries
#
# Produces both .apk (OpenWrt snapshot) and .ipk (OpenWrt stable) containing:
#   /usr/bin/kestreld    — HTTP status/device daemon (extra-networks/kestreld-rs)
#   /usr/bin/nft-resolve  — DNS blocklist resolver   (split-routing/nft-resolve-rs)
#   /etc/init.d/kestreld — procd service script
#
# Targets:
#   make build    — cross-compile both binaries for aarch64 musl
#   make package  — build + assemble both .apk and .ipk
#   make release  — package + create GitHub release (uploads both packages)
#   make deploy   — package + scp to router, auto-detects apk vs opkg
#   make clean    — remove build artefacts from both crates
#
# Variables (override on command line):
#   ROUTER=192.168.1.1          target router IP for `make deploy`
#   ARCH=aarch64                apk architecture  (check: apk info --print-arch)
#   OPENWRT_ARCH=aarch64_cortex-a53  ipk architecture  (check: opkg print-architecture)

CROSS_TARGET ?= aarch64-unknown-linux-musl
ARCH         ?= aarch64
OPENWRT_ARCH ?= aarch64_cortex-a53
ROUTER       ?=

PKG_NAME    := extra-networks
PKG_VERSION := $(shell cargo metadata --no-deps --format-version 1 \
                 --manifest-path extra-networks/kestreld-rs/Cargo.toml \
                 | python3 -c "import json,sys; d=json.load(sys.stdin); \
                   print(next(p['version'] for p in d['packages'] \
                         if p['name']=='kestreld'))")
PKG_REL     := r0
PKG_VER_FULL := $(PKG_VERSION)-$(PKG_REL)

UI_BIN      := extra-networks/kestreld-rs/target/$(CROSS_TARGET)/release/kestreld
NFT_BIN     := split-routing/nft-resolve-rs/target/$(CROSS_TARGET)/release/nft-resolve

OUTDIR      := target/pkg
# staging: installed file tree + apk meta files
STAGING     := $(OUTDIR)/staging
# control: ipk control directory
CONTROL     := $(OUTDIR)/control

APK_OUT     := $(OUTDIR)/$(PKG_NAME)-$(PKG_VER_FULL).$(ARCH).apk
IPK_OUT     := $(OUTDIR)/$(PKG_NAME)_$(PKG_VERSION)-1_$(OPENWRT_ARCH).ipk
SRC_TARBALL := $(OUTDIR)/$(PKG_NAME)-$(PKG_VERSION)-aarch64-musl.tar.gz

.PHONY: all build package release deploy clean

all: package

# ── build ─────────────────────────────────────────────────────────────────────

build: $(UI_BIN) $(NFT_BIN)

$(UI_BIN):
	cross build --release --target $(CROSS_TARGET) \
	  --manifest-path extra-networks/kestreld-rs/Cargo.toml

$(NFT_BIN):
	cross build --release --target $(CROSS_TARGET) \
	  --manifest-path split-routing/nft-resolve-rs/Cargo.toml

# ── shared staging ────────────────────────────────────────────────────────────

$(STAGING)/.staged: $(UI_BIN) $(NFT_BIN) release/files/kestreld.init
	rm -rf $(STAGING) $(CONTROL)
	mkdir -p $(STAGING)/usr/bin $(STAGING)/etc/init.d $(CONTROL)
	install -m 0755 $(UI_BIN)                       $(STAGING)/usr/bin/kestreld
	install -m 0755 $(NFT_BIN)                      $(STAGING)/usr/bin/nft-resolve
	install -m 0755 release/files/kestreld.init    $(STAGING)/etc/init.d/kestreld
	touch $@

# ── .apk (OpenWrt snapshot / apk) ────────────────────────────────────────────
# Install with: apk add --allow-untrusted /tmp/extra-networks-*.apk

package: $(APK_OUT) $(IPK_OUT)

$(APK_OUT): $(STAGING)/.staged
	@echo "==> $(notdir $(APK_OUT))"
	printf 'pkgname = %s\npkgver = %s\narch = %s\nsize = %s\npkgdesc = %s\nurl = %s\nbuilddate = %s\npackager = %s\n' \
	  '$(PKG_NAME)' '$(PKG_VER_FULL)' '$(ARCH)' \
	  "$$(find $(STAGING)/usr $(STAGING)/etc -type f | xargs du -b | awk '{s+=$$1}END{print s}')" \
	  'Extra-networks router UI + nft-resolve blocklist resolver' \
	  'https://github.com/lanbat/openwrt-kestrel' \
	  "$$(date +%s)" \
	  'Kiril Momchilov <momchilov@gmail.com>' \
	  > $(STAGING)/.PKGINFO
	printf '#!/bin/sh\n/etc/init.d/kestreld enable\n/etc/init.d/kestreld start\n' \
	  > $(STAGING)/.post-install
	printf '#!/bin/sh\n/etc/init.d/kestreld stop\n/etc/init.d/kestreld disable\n' \
	  > $(STAGING)/.pre-deinstall
	chmod 0755 $(STAGING)/.post-install $(STAGING)/.pre-deinstall
	mkdir -p $(OUTDIR)
	tar -czf $(APK_OUT) -C $(STAGING) .PKGINFO .post-install .pre-deinstall usr etc

# ── .ipk (OpenWrt stable / opkg) ─────────────────────────────────────────────
# Install with: opkg install --force-reinstall /tmp/extra-networks_*.ipk

$(IPK_OUT): $(STAGING)/.staged
	@echo "==> $(notdir $(IPK_OUT))"
	printf '%s\n' \
	  'Package: $(PKG_NAME)' \
	  'Version: $(PKG_VERSION)-1' \
	  'Architecture: $(OPENWRT_ARCH)' \
	  'Maintainer: Kiril Momchilov <momchilov@gmail.com>' \
	  'Source: https://github.com/lanbat/openwrt-kestrel' \
	  'Description: Extra-networks router UI + nft-resolve blocklist resolver' \
	  ' /usr/bin/kestreld   — HTTP daemon for /cgi-bin/status and /cgi-bin/device' \
	  ' /usr/bin/nft-resolve — DNS blocklist to nftables set resolver' \
	  > $(CONTROL)/control
	printf '#!/bin/sh\n[ -n "$$IPKG_INSTROOT" ] && exit 0\n/etc/init.d/kestreld enable\n/etc/init.d/kestreld start\n' \
	  > $(CONTROL)/postinst
	printf '#!/bin/sh\n[ -n "$$IPKG_INSTROOT" ] && exit 0\n/etc/init.d/kestreld stop\n/etc/init.d/kestreld disable\n' \
	  > $(CONTROL)/prerm
	chmod 0755 $(CONTROL)/postinst $(CONTROL)/prerm
	mkdir -p $(OUTDIR)
	tar -czf $(OUTDIR)/data.tar.gz    -C $(STAGING) usr etc
	tar -czf $(OUTDIR)/control.tar.gz -C $(CONTROL) .
	printf '2.0\n' > $(OUTDIR)/debian-binary
	ar cr $(IPK_OUT) \
	  $(OUTDIR)/debian-binary \
	  $(OUTDIR)/control.tar.gz \
	  $(OUTDIR)/data.tar.gz
	rm -f $(OUTDIR)/debian-binary $(OUTDIR)/data.tar.gz $(OUTDIR)/control.tar.gz

# ── release ───────────────────────────────────────────────────────────────────
# Requires: gh (GitHub CLI) authenticated, and a git remote named 'origin'.

release: package
	@git diff --quiet HEAD || { echo "ERROR: uncommitted changes"; exit 1; }
	tar -czf $(SRC_TARBALL) \
	  -C $(STAGING)/usr/bin kestreld nft-resolve
	@git tag --list v$(PKG_VERSION) | grep -q . \
	  && echo "WARN: tag v$(PKG_VERSION) already exists — skipping tag" \
	  || git tag -a v$(PKG_VERSION) -m "v$(PKG_VERSION)"
	git push origin v$(PKG_VERSION)
	gh release create v$(PKG_VERSION) \
	  $(APK_OUT) \
	  $(IPK_OUT) \
	  $(SRC_TARBALL) \
	  --title "v$(PKG_VERSION)" \
	  --notes "extra-networks $(PKG_VERSION) — kestreld + nft-resolve, aarch64 musl"
	@echo ""
	@sha256sum $(SRC_TARBALL) | awk '{print "Next: set release/openwrt/Makefile PKG_HASH =", $$1}'

# ── deploy ────────────────────────────────────────────────────────────────────

deploy: package
	@[ -n "$(ROUTER)" ] || { echo "Usage: make deploy ROUTER=<ip>"; exit 1; }
	@PKG_MGR=$$(ssh root@$(ROUTER) 'command -v apk >/dev/null 2>&1 && echo apk || echo opkg'); \
	if [ "$$PKG_MGR" = "apk" ]; then \
	  echo "==> apk detected — $(notdir $(APK_OUT))"; \
	  scp $(APK_OUT) root@$(ROUTER):/tmp/; \
	  ssh root@$(ROUTER) "apk add --allow-untrusted /tmp/$(notdir $(APK_OUT))"; \
	else \
	  echo "==> opkg detected — $(notdir $(IPK_OUT))"; \
	  scp $(IPK_OUT) root@$(ROUTER):/tmp/; \
	  ssh root@$(ROUTER) "opkg install --force-reinstall /tmp/$(notdir $(IPK_OUT))"; \
	fi

# ── clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf target/pkg
	cargo clean --manifest-path extra-networks/kestreld-rs/Cargo.toml
	cargo clean --manifest-path split-routing/nft-resolve-rs/Cargo.toml
