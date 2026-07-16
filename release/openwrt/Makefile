#
# OpenWrt package feed Makefile for kestreld.
#
# Usage with OpenWrt SDK:
#   1. Symlink or copy this directory into package/feeds/local/kestreld/
#   2. Run: make package/kestreld/compile
#   3. Find the .ipk in bin/packages/<arch>/local/
#
# The package downloads a pre-built musl binary from the GitHub release
# rather than building Rust inside the OpenWrt build system.
#
# To update to a new version:
#   1. Run `make release` in extra-networks/kestreld-rs/ to build and upload
#      the binary tarball to GitHub.
#   2. Update PKG_VERSION and PKG_HASH below.

include $(TOPDIR)/rules.mk

PKG_NAME    := kestreld
PKG_VERSION := 0.1.0
PKG_RELEASE := 1

# GitHub release tarball: kestreld-<version>-aarch64-musl.tar.gz
# containing a single file: kestreld (the stripped static binary)
PKG_SOURCE_URL  := https://github.com/lanbat/openwrt-kestrel/releases/download/v$(PKG_VERSION)
PKG_SOURCE      := $(PKG_NAME)-$(PKG_VERSION)-aarch64-musl.tar.gz
PKG_HASH        := skip  # replace with sha256sum output after first release

PKG_BUILD_DIR   := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_UNPACK      := $(HOST_TAR) -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION    := net
  CATEGORY   := Network
  TITLE      := Extra-networks router UI daemon
  URL        := https://github.com/lanbat/openwrt-kestrel
  DEPENDS    :=
endef

define Package/$(PKG_NAME)/description
  Rust HTTP daemon that replaces the extra-networks shell CGI scripts for
  /cgi-bin/status and /cgi-bin/device.  Serves pre-fetched, 5-second TTL
  cached state with no per-request subprocess overhead.
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
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kestreld $(1)/usr/bin/kestreld

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ../files/kestreld.init $(1)/etc/init.d/kestreld
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/kestreld enable
/etc/init.d/kestreld start
exit 0
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/kestreld stop
/etc/init.d/kestreld disable
exit 0
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
