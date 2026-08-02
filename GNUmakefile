# GNUmakefile — build, package, and release the openwrt-kestrel Rust binaries
#
# Produces both .apk (OpenWrt snapshot) and .ipk (OpenWrt stable) containing:
#   /usr/bin/kestreld    — router UI, run by uhttpd as a CGI binary via
#                          symlinks under /www/cgi-bin/ (networks/kestreld-rs)
#   /usr/bin/nft-resolve — DNS blocklist resolver (split-routing/nft-resolve-rs)
#
# No daemon, no extra port, no reverse proxy: uhttpd invokes kestreld fresh
# per request, same as any other CGI script.
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
#   BUILD_STD=yes               rebuild std from source instead of using a
#                               prebuilt one — required for mips/mipsel-
#                               unknown-linux-musl, which stable Rust no
#                               longer ships prebuilt std for (demoted to
#                               tier 3: https://github.com/rust-lang/rust/pull/115238).
#                               Needs a nightly toolchain with the rust-src
#                               component installed.

CROSS_TARGET ?= aarch64-unknown-linux-musl
ARCH         ?= aarch64
OPENWRT_ARCH ?= aarch64_cortex-a53
ROUTER       ?=
BUILD_STD    ?= no

# `cross`, when invoked with `--manifest-path <subdir>/Cargo.toml` (as every
# recipe below does), doesn't reliably auto-discover Cross.toml at the repo
# root — confirmed directly: mips/mipsel silently fell back to the host
# linker and failed ("relocations in generic ELF") until CROSS_CONFIG was
# set explicitly. Pass it for every target so this never depends on cross's
# own discovery behavior.
export CROSS_CONFIG := $(CURDIR)/Cross.toml

ifeq ($(BUILD_STD),yes)
CROSS_BUILD := cross +nightly build -Z build-std=std,panic_abort --release --target $(CROSS_TARGET)
CROSS_RUN   := cross +nightly run -Z build-std=std,panic_abort --release --target $(CROSS_TARGET)
else
CROSS_BUILD := cross build --release --target $(CROSS_TARGET)
CROSS_RUN   := cross run --release --target $(CROSS_TARGET)
endif

PKG_NAME    := kestrel
PKG_VERSION := $(shell cargo metadata --no-deps --format-version 1 \
                 --manifest-path networks/kestreld-rs/Cargo.toml \
                 | python3 -c "import json,sys; d=json.load(sys.stdin); \
                   print(next(p['version'] for p in d['packages'] \
                         if p['name']=='kestreld'))")
PKG_REL     := r0
PKG_VER_FULL := $(PKG_VERSION)-$(PKG_REL)

UI_BIN      := networks/kestreld-rs/target/$(CROSS_TARGET)/release/kestreld
NFT_BIN     := split-routing/nft-resolve-rs/target/$(CROSS_TARGET)/release/nft-resolve

OUTDIR      := target/pkg
# staging: installed file tree + apk meta files
STAGING     := $(OUTDIR)/staging
# control: ipk control directory
CONTROL     := $(OUTDIR)/control

APK_OUT     := $(OUTDIR)/$(PKG_NAME)-$(PKG_VER_FULL).$(ARCH).apk
IPK_OUT     := $(OUTDIR)/$(PKG_NAME)_$(PKG_VERSION)-1_$(OPENWRT_ARCH).ipk
SRC_TARBALL := $(OUTDIR)/$(PKG_NAME)-$(PKG_VERSION)-aarch64-musl.tar.gz

# ── social-firewall: a second, fully independent package ─────────────────────
# Separate .apk/.ipk/GitHub release from kestrel's own — installable and
# removable independently. Reuses the same CROSS_BUILD/CROSS_CONFIG
# machinery, own staging dir so the two packages' file trees never mix.

SF_PKG_NAME    := social-firewall
SF_PKG_VERSION := $(shell cargo metadata --no-deps --format-version 1 \
                    --manifest-path social-firewall/Cargo.toml \
                    | python3 -c "import json,sys; d=json.load(sys.stdin); \
                      print(next(p['version'] for p in d['packages'] \
                            if p['name']=='sf-cli'))")
SF_PKG_REL     := r0
SF_PKG_VER_FULL := $(SF_PKG_VERSION)-$(SF_PKG_REL)

SF_BIN         := social-firewall/target/$(CROSS_TARGET)/release/sf

SF_STAGING     := $(OUTDIR)/sf-staging
SF_CONTROL     := $(OUTDIR)/sf-control

SF_APK_OUT     := $(OUTDIR)/$(SF_PKG_NAME)-$(SF_PKG_VER_FULL).$(ARCH).apk
SF_IPK_OUT     := $(OUTDIR)/$(SF_PKG_NAME)_$(SF_PKG_VERSION)-1_$(OPENWRT_ARCH).ipk
SF_SRC_TARBALL := $(OUTDIR)/$(SF_PKG_NAME)-$(SF_PKG_VERSION)-aarch64-musl.tar.gz

.PHONY: all build package release deploy clean smoke-test \
        build-social-firewall package-social-firewall release-social-firewall \
        deploy-social-firewall clean-social-firewall

all: package

# ── build ─────────────────────────────────────────────────────────────────────

build: $(UI_BIN) $(NFT_BIN)

$(UI_BIN):
	$(CROSS_BUILD) --manifest-path networks/kestreld-rs/Cargo.toml

$(NFT_BIN):
	$(CROSS_BUILD) --manifest-path split-routing/nft-resolve-rs/Cargo.toml

# ── shared staging ────────────────────────────────────────────────────────────

$(STAGING)/.staged: $(UI_BIN) $(NFT_BIN)
	rm -rf $(STAGING) $(CONTROL)
	mkdir -p $(STAGING)/usr/bin $(STAGING)/www/cgi-bin $(CONTROL)
	install -m 0755 $(UI_BIN)  $(STAGING)/usr/bin/kestreld
	install -m 0755 $(NFT_BIN) $(STAGING)/usr/bin/nft-resolve
	for ep in status device network identity qr approve-access approve-join rotate-password; do \
	  ln -sf /usr/bin/kestreld $(STAGING)/www/cgi-bin/$$ep; \
	done
	touch $@

# ── .apk (OpenWrt snapshot / apk) ────────────────────────────────────────────
# Install with: apk add --allow-untrusted /tmp/kestrel-*.apk

package: $(APK_OUT) $(IPK_OUT)

$(APK_OUT): $(STAGING)/.staged
	@echo "==> $(notdir $(APK_OUT))"
	printf 'pkgname = %s\npkgver = %s\narch = %s\nsize = %s\npkgdesc = %s\nurl = %s\nbuilddate = %s\npackager = %s\n' \
	  '$(PKG_NAME)' '$(PKG_VER_FULL)' '$(ARCH)' \
	  "$$(find $(STAGING)/usr $(STAGING)/www -type f | xargs du -b | awk '{s+=$$1}END{print s}')" \
	  'kestrel: isolated-network router UI (kestreld) + nft-resolve blocklist resolver' \
	  'https://github.com/lanbat/openwrt-kestrel' \
	  "$$(date +%s)" \
	  'Kiril Momchilov <momchilov@gmail.com>' \
	  > $(STAGING)/.PKGINFO
	mkdir -p $(OUTDIR)
	tar -czf $(APK_OUT) -C $(STAGING) .PKGINFO usr www

# ── .ipk (OpenWrt stable / opkg) ─────────────────────────────────────────────
# Install with: opkg install --force-reinstall /tmp/kestrel_*.ipk

$(IPK_OUT): $(STAGING)/.staged
	@echo "==> $(notdir $(IPK_OUT))"
	printf '%s\n' \
	  'Package: $(PKG_NAME)' \
	  'Version: $(PKG_VERSION)-1' \
	  'Architecture: $(OPENWRT_ARCH)' \
	  'Maintainer: Kiril Momchilov <momchilov@gmail.com>' \
	  'Source: https://github.com/lanbat/openwrt-kestrel' \
	  'Description: kestrel: isolated-network router UI (kestreld) + nft-resolve blocklist resolver' \
	  ' /usr/bin/kestreld   — CGI binary for /cgi-bin/{status,device,network,identity,qr,approve-access,approve-join,rotate-password}' \
	  ' /usr/bin/nft-resolve — DNS blocklist to nftables set resolver' \
	  > $(CONTROL)/control
	mkdir -p $(OUTDIR)
	tar -czf $(OUTDIR)/data.tar.gz    -C $(STAGING) usr www
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
	  --notes "kestrel $(PKG_VERSION) — kestreld + nft-resolve, aarch64 musl"
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

# ── smoke test ────────────────────────────────────────────────────────────────
# A binary can cross-compile clean and still crash immediately on real
# hardware if the target's baseline ISA assumption is wrong (SIGILL, wrong
# dynamic linker path, etc). cross's images bundle qemu-user emulation, so
# `cross run` exercises the real startup path under emulation. Used by CI;
# skipped there for x86_64, which runs natively on the runner already.

smoke-test: $(UI_BIN) $(NFT_BIN)
	$(CROSS_RUN) --manifest-path networks/kestreld-rs/Cargo.toml \
	  -- --rotate-apply __smoketest__ /tmp/__smoketest_missing_pwfile__
	$(CROSS_RUN) --manifest-path split-routing/nft-resolve-rs/Cargo.toml \
	  -- --help

# ── clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf target/pkg
	cargo clean --manifest-path networks/kestreld-rs/Cargo.toml
	cargo clean --manifest-path split-routing/nft-resolve-rs/Cargo.toml

# ── social-firewall: build ────────────────────────────────────────────────────

build-social-firewall: $(SF_BIN)

$(SF_BIN):
	$(CROSS_BUILD) --manifest-path social-firewall/Cargo.toml -p sf-cli

$(SF_STAGING)/.staged: $(SF_BIN)
	rm -rf $(SF_STAGING) $(SF_CONTROL)
	mkdir -p $(SF_STAGING)/usr/bin $(SF_CONTROL)
	install -m 0755 $(SF_BIN) $(SF_STAGING)/usr/bin/sf
	touch $@

# ── social-firewall: .apk ─────────────────────────────────────────────────────

package-social-firewall: $(SF_APK_OUT) $(SF_IPK_OUT)

$(SF_APK_OUT): $(SF_STAGING)/.staged
	@echo "==> $(notdir $(SF_APK_OUT))"
	printf 'pkgname = %s\npkgver = %s\narch = %s\nsize = %s\npkgdesc = %s\nurl = %s\nbuilddate = %s\npackager = %s\n' \
	  '$(SF_PKG_NAME)' '$(SF_PKG_VER_FULL)' '$(ARCH)' \
	  "$$(find $(SF_STAGING)/usr -type f | xargs du -b | awk '{s+=$$1}END{print s}')" \
	  'social-firewall: decentralized, opinion-based firewall policy (optional, independent of kestrel)' \
	  'https://github.com/lanbat/openwrt-kestrel' \
	  "$$(date +%s)" \
	  'Kiril Momchilov <momchilov@gmail.com>' \
	  > $(SF_STAGING)/.PKGINFO
	mkdir -p $(OUTDIR)
	tar -czf $(SF_APK_OUT) -C $(SF_STAGING) .PKGINFO usr

# ── social-firewall: .ipk ─────────────────────────────────────────────────────

$(SF_IPK_OUT): $(SF_STAGING)/.staged
	@echo "==> $(notdir $(SF_IPK_OUT))"
	printf '%s\n' \
	  'Package: $(SF_PKG_NAME)' \
	  'Version: $(SF_PKG_VERSION)-1' \
	  'Architecture: $(OPENWRT_ARCH)' \
	  'Maintainer: Kiril Momchilov <momchilov@gmail.com>' \
	  'Source: https://github.com/lanbat/openwrt-kestrel' \
	  'Description: social-firewall: decentralized, opinion-based firewall policy (optional, independent of kestrel)' \
	  ' /usr/bin/sf — social-firewall local-node CLI + cron-driven policy applier' \
	  > $(SF_CONTROL)/control
	rm -rf $(OUTDIR)/sf-ipk-tmp
	mkdir -p $(OUTDIR)/sf-ipk-tmp
	tar -czf $(OUTDIR)/sf-ipk-tmp/data.tar.gz    -C $(SF_STAGING) usr
	tar -czf $(OUTDIR)/sf-ipk-tmp/control.tar.gz -C $(SF_CONTROL) .
	printf '2.0\n' > $(OUTDIR)/sf-ipk-tmp/debian-binary
	ar cr $(SF_IPK_OUT) \
	  $(OUTDIR)/sf-ipk-tmp/debian-binary \
	  $(OUTDIR)/sf-ipk-tmp/control.tar.gz \
	  $(OUTDIR)/sf-ipk-tmp/data.tar.gz
	rm -rf $(OUTDIR)/sf-ipk-tmp

# ── social-firewall: release ──────────────────────────────────────────────────

release-social-firewall: package-social-firewall
	@git diff --quiet HEAD || { echo "ERROR: uncommitted changes"; exit 1; }
	tar -czf $(SF_SRC_TARBALL) -C $(SF_STAGING)/usr/bin sf
	@git tag --list sf-v$(SF_PKG_VERSION) | grep -q . \
	  && echo "WARN: tag sf-v$(SF_PKG_VERSION) already exists — skipping tag" \
	  || git tag -a sf-v$(SF_PKG_VERSION) -m "social-firewall v$(SF_PKG_VERSION)"
	git push origin sf-v$(SF_PKG_VERSION)
	gh release create sf-v$(SF_PKG_VERSION) \
	  $(SF_APK_OUT) \
	  $(SF_IPK_OUT) \
	  $(SF_SRC_TARBALL) \
	  --title "social-firewall v$(SF_PKG_VERSION)" \
	  --notes "social-firewall $(SF_PKG_VERSION) — sf CLI, aarch64 musl"
	@echo ""
	@sha256sum $(SF_SRC_TARBALL) | awk '{print "Next: set release/openwrt/social-firewall/Makefile PKG_HASH =", $$1}'

# ── social-firewall: deploy ───────────────────────────────────────────────────

deploy-social-firewall: package-social-firewall
	@[ -n "$(ROUTER)" ] || { echo "Usage: make deploy-social-firewall ROUTER=<ip>"; exit 1; }
	@PKG_MGR=$$(ssh root@$(ROUTER) 'command -v apk >/dev/null 2>&1 && echo apk || echo opkg'); \
	if [ "$$PKG_MGR" = "apk" ]; then \
	  echo "==> apk detected — $(notdir $(SF_APK_OUT))"; \
	  scp $(SF_APK_OUT) root@$(ROUTER):/tmp/; \
	  ssh root@$(ROUTER) "apk add --allow-untrusted /tmp/$(notdir $(SF_APK_OUT))"; \
	else \
	  echo "==> opkg detected — $(notdir $(SF_IPK_OUT))"; \
	  scp $(SF_IPK_OUT) root@$(ROUTER):/tmp/; \
	  ssh root@$(ROUTER) "opkg install --force-reinstall /tmp/$(notdir $(SF_IPK_OUT))"; \
	fi

# ── social-firewall: clean ────────────────────────────────────────────────────

clean-social-firewall:
	rm -rf $(SF_STAGING) $(SF_CONTROL)
	cargo clean --manifest-path social-firewall/Cargo.toml
