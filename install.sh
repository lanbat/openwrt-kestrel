#!/bin/sh
# Top-level installer — runs each sub-project's install.sh in order.
# Each sub-script is self-contained and can also be run directly.
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"

[ $# -gt 0 ] && case "$1" in
    networks)        sh "$REPO/networks/install.sh";      exit ;;
    split-routing)   sh "$REPO/split-routing/install.sh"; exit ;;
    # Optional, independent package — never run by the no-arg default
    # below. Not a dependency of (and has no dependency on) kestrel/
    # split-routing; install/remove it separately, on purpose.
    social-firewall) shift; sh "$REPO/social-firewall/install.sh" "$@"; exit ;;
esac

sh "$REPO/networks/install.sh"
sh "$REPO/split-routing/install.sh"
