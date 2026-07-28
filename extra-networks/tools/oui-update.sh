#!/bin/sh
# Downloads OUI prefix databases from multiple sources and merges them into
# /etc/kestrel/networks/oui.txt for manufacturer lookups on the device page.
#
# Sources (tried in priority order; all are attempted regardless of failures):
#   1. Wireshark manuf  — community-maintained, most complete, all prefix lengths
#   2. IEEE MA-L        — 24-bit OUI assignments
#   3. IEEE MA-M        — 28-bit OUI assignments (large vendors, more specific)
#   4. IEEE MA-S        — 36-bit OUI assignments (product-level blocks)
#
# Output format: PREFIX<TAB>NAME, where PREFIX is 6, 7, or 9 uppercase hex chars
# (no colons) corresponding to 24-, 28-, and 36-bit blocks respectively.
# Longer prefixes take precedence over shorter ones at lookup time.

BASE_DIR=/etc/kestrel/networks
_out="${BASE_DIR}/oui.txt"
_tmp=$(mktemp /tmp/oui-update.XXXXXX 2>/dev/null || printf '/tmp/oui-update.tmp')
_ok=0

_fetch_wireshark() {
    curl -sf --max-time 60 \
        'https://www.wireshark.org/download/automated/data/manuf' \
    | awk -F'\t' '
        /^#/ || NF < 2 { next }
        {
            raw = $1
            sub(/\/[0-9]+$/, "", raw)
            gsub(/:/, "", raw)
            raw = toupper(raw)
            name = (NF >= 3 && $3 != "") ? $3 : $2
            gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", name)
            if (length(raw) >= 6 && name != "") printf "%s\t%s\n", raw, name
        }
    '
}

_fetch_ieee() {
    curl -sf --max-time 30 "$1" \
    | awk -F',' '
        NR == 1 { next }
        $2 != "" {
            name = $3
            gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", name)
            if (name != "") printf "%s\t%s\n", $2, name
        }
    '
}

printf 'Updating OUI database...\n'

if _fetch_wireshark >> "$_tmp" 2>/dev/null; then
    printf '  wireshark manuf : ok\n'
    _ok=$((_ok + 1))
else
    printf '  wireshark manuf : failed\n'
fi

for _src in \
    'https://standards-oui.ieee.org/oui/oui.csv|ieee MA-L (24-bit)' \
    'https://standards-oui.ieee.org/oui28/mam.csv|ieee MA-M (28-bit)' \
    'https://standards-oui.ieee.org/oui36/oui36.csv|ieee MA-S (36-bit)'; do
    _url="${_src%%|*}"; _lbl="${_src##*|}"
    if _fetch_ieee "$_url" >> "$_tmp" 2>/dev/null; then
        printf '  %-24s: ok\n' "$_lbl"
        _ok=$((_ok + 1))
    else
        printf '  %-24s: failed\n' "$_lbl"
    fi
done

if [ "$_ok" -eq 0 ]; then
    printf 'All sources failed — keeping existing database\n'
    rm -f "$_tmp"
    exit 1
fi

# Deduplicate by prefix — first occurrence wins (Wireshark is appended first
# so its entries take priority over raw IEEE data)
awk -F'\t' '!seen[$1]++' "$_tmp" > "${_tmp}.dedup" \
    && mv "${_tmp}.dedup" "$_out"
rm -f "$_tmp"
printf 'Done: %d entries\n' "$(wc -l < "$_out")"
