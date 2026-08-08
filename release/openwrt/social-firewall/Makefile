#
# OpenWrt package feed Makefile for social-firewall.
#
# A genuinely separate package from kestrel's own — installable and
# removable independently, with no dependency in either direction. See
# ../Makefile (kestrel's own) for the sibling this mirrors.
#
# Usage with OpenWrt SDK:
#   1. Symlink or copy this directory into package/feeds/local/social-firewall/
#   2. Run: make package/social-firewall/compile
#   3. Find the .ipk in bin/packages/<arch>/local/
#
# The package downloads a pre-built musl binary from the GitHub release
# rather than building Rust inside the OpenWrt build system.
#
# To update to a new version:
#   1. Run `make release-social-firewall` at the repo root to build and
#      upload the binary tarball to GitHub.
#   2. Update PKG_VERSION and PKG_HASH below.

include $(TOPDIR)/rules.mk

PKG_NAME    := social-firewall
PKG_VERSION := 0.0.1
PKG_RELEASE := 1

# GitHub release tarball: social-firewall-<version>-aarch64-musl.tar.gz
# containing the stripped `sf` and `kestrel-reticulum-bridge` binaries.
PKG_SOURCE_URL  := https://github.com/lanbat/openwrt-kestrel/releases/download/sf-v$(PKG_VERSION)
PKG_SOURCE      := $(PKG_NAME)-$(PKG_VERSION)-aarch64-musl.tar.gz
PKG_HASH        := skip  # replace with sha256sum output after first release

PKG_BUILD_DIR   := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_UNPACK      := $(HOST_TAR) -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION    := net
  CATEGORY   := Network
  TITLE      := Decentralized, opinion-based firewall policy
  URL        := https://github.com/lanbat/openwrt-kestrel
  DEPENDS    :=
endef

define Package/$(PKG_NAME)/description
  Rust CLI + cron-driven policy applier implementing a decentralized
  "social firewall": routers publish signed, reason-required opinions on
  domains/IPs, and aggregate opinions from trusted peers into local
  firewall enforcement (via a dedicated nftables table, never touching
  fw4 or any other package's rules). Entirely optional and independent of
  the kestrel package — neither depends on the other.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(PKG_UNPACK)
endef

define Build/Compile
	# pre-built binary — nothing to compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sf $(1)/usr/bin/sf
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kestrel-reticulum-bridge $(1)/usr/bin/kestrel-reticulum-bridge
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
