//! Ties `dhcp_fingerprint` and `mdns` together into a per-network registry
//! of *known identities*, decoupled from any single MAC — the whole point
//! being to recognize a device again after a privacy MAC randomization
//! rotates it. Matching is scored, not exact: no single signal here
//! reliably distinguishes two identical phones of the same model/OS
//! version from each other, so this only ever produces a *suggestion* for
//! a human to confirm on the join-approval prompt, never a silent
//! auto-reapplied label.
//!
//! Identities are keyed by an opaque generated `id`, not by the label
//! string: keying by label directly has two real failure modes — renaming
//! a device would silently orphan its whole fingerprint history (no entry
//! exists under the new string), and giving two genuinely different
//! devices the same label text (e.g. replacing a phone and keeping the
//! old name) would merge their fingerprints into one polluted record. An
//! opaque id sidesteps both: `rename` updates the label in place without
//! touching history, and nothing ever merges into an existing identity
//! except through an explicit confirmed match (`merge_into`).

use std::path::Path;
use tokio::io::AsyncReadExt;

use crate::data::{dhcp_fingerprint::DhcpFingerprint, files, mdns::MdnsInfo};
use crate::db::{FingerprintRow, Store};

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The fingerprint signals gathered for one specific, not-yet-identified
/// join — nothing here is tied to a label yet.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub dhcp: DhcpFingerprint,
    pub mdns: MdnsInfo,
    pub wifi_caps: String,
    pub browser_cookie: String,
    pub http_headers: String,
    pub tcp_syn: String,
    pub tls_clienthello: String,
    pub quic_initial: String,
}

/// A normalized observation retained as historical evidence. Values are
/// bounded fingerprints, never raw packets or HTTP headers.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EvidenceObservation {
    pub signal: String,
    pub value: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub observations: u32,
}

impl Observed {
    /// `net` is the network name (e.g. "guest"), used to resolve the
    /// hostapd radio serving it for the WiFi-capability signal.
    /// `bridge_ip` must be an address on the same bridge as `ip` (e.g.
    /// the network's gateway address) — see `mdns::lookup_device_info`
    /// for why.
    pub async fn gather(logs: &[String], net: &str, mac: &str, ip: &str, bridge_ip: &str) -> Self {
        let dhcp = crate::data::dhcp_fingerprint::parse_all(logs)
            .remove(mac)
            .unwrap_or_default();
        let mdns = crate::data::mdns::lookup_device_info(bridge_ip, ip)
            .await
            .unwrap_or_default();
        let wifi_caps = crate::data::wifi_caps::capabilities(net, mac).await;
        Self {
            dhcp,
            mdns,
            wifi_caps,
            ..Default::default()
        }
    }
}

/// One registered identity: an opaque id, its current label, the
/// fingerprint last observed for it, and every MAC that identity has ever
/// shown up as.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintRecord {
    pub id: String,
    pub label: String,
    pub dhcp_options: String,
    pub dhcp_vendor: String,
    pub wifi_caps: String,
    pub mdns_name: String,
    pub mdns_model: String,
    pub macs: Vec<String>,
    pub last_seen: u64,
    /// When this identity was first registered — set once by `create`,
    /// never touched by `merge_into`/`rename`.
    pub first_seen: u64,
    /// Past (label, timestamp it stopped being current) pairs, oldest
    /// first — `rename` appends to this rather than discarding the old
    /// label, so a rename never loses the identity's naming history.
    pub label_history: Vec<(String, u64)>,
    pub browser_cookie: String,
    pub http_headers: String,
    pub tcp_syn: String,
    pub tls_clienthello: String,
    pub quic_initial: String,
    pub evidence: Vec<EvidenceObservation>,
}

/// `label_history` entries are encoded as `label@timestamp`, joined by
/// `|` — labels are free text (see the "allow any text as device label"
/// history in this project), so a label containing a literal `@` or `|`
/// would confuse this encoding. Same trust level as the rest of this
/// project's tab-separated file formats (a device-labels entry with a
/// literal tab would break the same way): fine for a home router admin's
/// own input, not hardened against adversarial label text.
pub(crate) fn encode_label_history(history: &[(String, u64)]) -> String {
    history
        .iter()
        .map(|(label, ts)| format!("{label}@{ts}"))
        .collect::<Vec<_>>()
        .join("|")
}

pub(crate) fn parse_label_history(s: &str) -> Vec<(String, u64)> {
    s.split('|')
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (label, ts) = e.rsplit_once('@')?;
            Some((label.to_string(), ts.parse().unwrap_or(0)))
        })
        .collect()
}

pub async fn read_registry(store: &Store, iface: &str) -> Vec<FingerprintRecord> {
    store
        .read_fingerprint_registry(iface)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(row_to_record)
        .collect()
}

/// The identity `mac` currently belongs to, if any — used both to offer a
/// suggestion and to find what needs renaming when a device's label is
/// edited.
pub fn find_by_mac<'a>(
    records: &'a [FingerprintRecord],
    mac: &str,
) -> Option<&'a FingerprintRecord> {
    let mac = mac.to_lowercase();
    records.iter().find(|r| r.macs.contains(&mac))
}

fn row_to_record(r: FingerprintRow) -> FingerprintRecord {
    FingerprintRecord {
        id: r.id,
        label: r.label,
        dhcp_options: r.dhcp_options,
        dhcp_vendor: r.dhcp_vendor,
        wifi_caps: r.wifi_caps,
        mdns_name: r.mdns_name,
        mdns_model: r.mdns_model,
        macs: r
            .macs
            .split(',')
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty())
            .collect(),
        last_seen: r.last_seen as u64,
        first_seen: r.first_seen as u64,
        label_history: parse_label_history(&r.label_history),
        browser_cookie: r.browser_cookie,
        http_headers: r.http_headers,
        tcp_syn: r.tcp_syn,
        tls_clienthello: r.tls_clienthello,
        quic_initial: r.quic_initial,
        evidence: serde_json::from_str(&r.evidence_json).unwrap_or_default(),
    }
}

fn record_to_row(r: &FingerprintRecord) -> FingerprintRow {
    FingerprintRow {
        id: r.id.clone(),
        label: r.label.clone(),
        dhcp_options: r.dhcp_options.clone(),
        dhcp_vendor: r.dhcp_vendor.clone(),
        wifi_caps: r.wifi_caps.clone(),
        mdns_name: r.mdns_name.clone(),
        mdns_model: r.mdns_model.clone(),
        macs: r.macs.join(","),
        last_seen: r.last_seen as i64,
        first_seen: r.first_seen as i64,
        label_history: encode_label_history(&r.label_history),
        browser_cookie: r.browser_cookie.clone(),
        http_headers: r.http_headers.clone(),
        tcp_syn: r.tcp_syn.clone(),
        tls_clienthello: r.tls_clienthello.clone(),
        quic_initial: r.quic_initial.clone(),
        evidence_json: serde_json::to_string(&r.evidence).unwrap_or_else(|_| "[]".into()),
    }
}

fn observed_signals(observed: &Observed) -> Vec<(&'static str, String, f32)> {
    let mut out = Vec::new();
    if !observed.mdns.name.is_empty() {
        out.push(("mdns_name", observed.mdns.name.clone(), 50.0));
    }
    if !observed.mdns.model.is_empty() {
        out.push(("mdns_model", observed.mdns.model.clone(), 15.0));
    }
    if !observed.wifi_caps.is_empty() {
        out.push(("wifi_caps", observed.wifi_caps.clone(), 15.0));
    }
    if !observed.dhcp.vendor_class.is_empty() {
        out.push(("dhcp_vendor", observed.dhcp.vendor_class.clone(), 10.0));
    }
    if !observed.dhcp.requested_options.is_empty() {
        out.push((
            "dhcp_options",
            observed.dhcp.requested_options.clone(),
            10.0,
        ));
    }
    if !observed.browser_cookie.is_empty() {
        out.push(("browser_cookie", observed.browser_cookie.clone(), 35.0));
    }
    if !observed.http_headers.is_empty() {
        out.push(("http_headers", observed.http_headers.clone(), 10.0));
    }
    if !observed.tcp_syn.is_empty() {
        out.push(("tcp_syn", observed.tcp_syn.clone(), 8.0));
    }
    if !observed.tls_clienthello.is_empty() {
        out.push(("tls_clienthello", observed.tls_clienthello.clone(), 12.0));
    }
    if !observed.quic_initial.is_empty() {
        out.push(("quic_initial", observed.quic_initial.clone(), 12.0));
    }
    out
}

fn record_evidence(record: &mut FingerprintRecord, observed: &Observed, now_ts: u64) {
    for (signal, value, _) in observed_signals(observed) {
        if let Some(existing) = record
            .evidence
            .iter_mut()
            .find(|item| item.signal == signal && item.value == value)
        {
            existing.last_seen = now_ts;
            existing.observations = existing.observations.saturating_add(1);
        } else {
            record.evidence.push(EvidenceObservation {
                signal: signal.into(),
                value,
                first_seen: now_ts,
                last_seen: now_ts,
                observations: 1,
            });
        }
    }
    // Keep the registry bounded when a signal legitimately changes over a
    // device's lifetime, while retaining enough history to distinguish a
    // stable value from a one-off observation.
    for signal in [
        "mdns_name",
        "mdns_model",
        "wifi_caps",
        "dhcp_vendor",
        "dhcp_options",
        "browser_cookie",
        "http_headers",
        "tcp_syn",
        "tls_clienthello",
        "quic_initial",
    ] {
        let mut indexes: Vec<usize> = record
            .evidence
            .iter()
            .enumerate()
            .filter(|(_, item)| item.signal == signal)
            .map(|(index, _)| index)
            .collect();
        while indexes.len() > 8 {
            let remove_at = indexes
                .iter()
                .copied()
                .min_by_key(|index| {
                    let item = &record.evidence[*index];
                    (item.last_seen, item.observations)
                })
                .unwrap();
            record.evidence.remove(remove_at);
            indexes = record
                .evidence
                .iter()
                .enumerate()
                .filter(|(_, item)| item.signal == signal)
                .map(|(index, _)| index)
                .collect();
        }
    }
}

async fn write_registry(store: &Store, iface: &str, records: &[FingerprintRecord]) {
    let rows: Vec<FingerprintRow> = records.iter().map(record_to_row).collect();
    let _ = store.write_fingerprint_registry(iface, &rows).await;
}

const FLAT_FILE_FIELDS: usize = 11;

/// Parses the legacy `{iface}-device-fingerprints` flat-file format —
/// used only by `migrate::migrate_fingerprints` to import a router's
/// existing registry into `Store`. Not part of the ongoing API (see
/// `read_registry`, which reads from `Store`); this exists purely so the
/// one-time importer doesn't need to duplicate the ad-hoc tab-separated
/// parsing this format has always used.
pub(crate) async fn read_registry_from_flat_file(path: &Path) -> Vec<FingerprintRecord> {
    files::read_lines(path)
        .await
        .iter()
        .filter_map(|line| parse_flat_file_record(line))
        .collect()
}

fn parse_flat_file_record(line: &str) -> Option<FingerprintRecord> {
    let f: Vec<&str> = line.splitn(FLAT_FILE_FIELDS, '\t').collect();
    if f.len() < FLAT_FILE_FIELDS || f[0].is_empty() || f[1].is_empty() {
        return None;
    }
    Some(FingerprintRecord {
        id: f[0].to_string(),
        label: f[1].to_string(),
        dhcp_options: f[2].to_string(),
        dhcp_vendor: f[3].to_string(),
        wifi_caps: f[4].to_string(),
        mdns_name: f[5].to_string(),
        mdns_model: f[6].to_string(),
        macs: f[7]
            .split(',')
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty())
            .collect(),
        last_seen: f[8].parse().unwrap_or(0),
        first_seen: f[9].parse().unwrap_or(0),
        label_history: parse_label_history(f[10]),
        browser_cookie: String::new(),
        http_headers: String::new(),
        tcp_syn: String::new(),
        tls_clienthello: String::new(),
        quic_initial: String::new(),
        evidence: Vec::new(),
    })
}

/// 8 random hex characters from `/dev/urandom` — same source
/// `routes::rotate_password::gen_password` already uses for generating
/// unguessable strings, just narrower output.
async fn gen_id() -> String {
    let mut buf = [0u8; 4];
    if let Ok(mut f) = tokio::fs::File::open("/dev/urandom").await {
        let _ = f.read_exact(&mut buf).await;
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn apply_observed(r: &mut FingerprintRecord, mac: &str, observed: &Observed, now_ts: u64) {
    if !r.macs.contains(&mac.to_string()) {
        r.macs.push(mac.to_string());
    }
    if !observed.dhcp.requested_options.is_empty() {
        r.dhcp_options = observed.dhcp.requested_options.clone();
    }
    if !observed.dhcp.vendor_class.is_empty() {
        r.dhcp_vendor = observed.dhcp.vendor_class.clone();
    }
    if !observed.wifi_caps.is_empty() {
        r.wifi_caps = observed.wifi_caps.clone();
    }
    if !observed.mdns.name.is_empty() {
        r.mdns_name = observed.mdns.name.clone();
    }
    if !observed.mdns.model.is_empty() {
        r.mdns_model = observed.mdns.model.clone();
    }
    for (dst, src) in [
        (&mut r.browser_cookie, &observed.browser_cookie),
        (&mut r.http_headers, &observed.http_headers),
        (&mut r.tcp_syn, &observed.tcp_syn),
        (&mut r.tls_clienthello, &observed.tls_clienthello),
        (&mut r.quic_initial, &observed.quic_initial),
    ] {
        if !src.is_empty() {
            *dst = src.clone();
        }
    }
    r.last_seen = now_ts;
    record_evidence(r, observed, now_ts);
}

/// Registers a brand-new identity (no confirmed match existed) for
/// `label`, seeded with whatever was observed for `mac`. Returns the
/// generated id.
pub async fn create(
    store: &Store,
    iface: &str,
    label: &str,
    mac: &str,
    observed: &Observed,
    now_ts: u64,
) -> String {
    let mut records = read_registry(store, iface).await;
    let id = gen_id().await;
    let mac = mac.to_lowercase();
    let mut record = FingerprintRecord {
        id: id.clone(),
        label: label.to_string(),
        dhcp_options: observed.dhcp.requested_options.clone(),
        dhcp_vendor: observed.dhcp.vendor_class.clone(),
        wifi_caps: observed.wifi_caps.clone(),
        mdns_name: observed.mdns.name.clone(),
        mdns_model: observed.mdns.model.clone(),
        macs: vec![mac],
        last_seen: now_ts,
        first_seen: now_ts,
        label_history: Vec::new(),
        browser_cookie: observed.browser_cookie.clone(),
        http_headers: observed.http_headers.clone(),
        tcp_syn: observed.tcp_syn.clone(),
        tls_clienthello: observed.tls_clienthello.clone(),
        quic_initial: observed.quic_initial.clone(),
        evidence: Vec::new(),
    };
    record_evidence(&mut record, observed, now_ts);
    records.push(record);
    write_registry(store, iface, &records).await;
    id
}

/// Confirmed-match path: folds `mac` into the *existing* identity `id`,
/// refreshing whichever fingerprint fields were actually captured this
/// time (an empty `Observed` field never overwrites a previously-known
/// one). Does not touch the label — that's `rename`'s job, kept separate
/// so a label edit later doesn't require re-confirming a match.
pub async fn merge_into(
    store: &Store,
    iface: &str,
    id: &str,
    mac: &str,
    observed: &Observed,
    now_ts: u64,
) {
    let mut records = read_registry(store, iface).await;
    let mac = mac.to_lowercase();
    if let Some(r) = records.iter_mut().find(|r| r.id == id) {
        apply_observed(r, &mac, observed, now_ts);
        write_registry(store, iface, &records).await;
    }
}

/// Updates the label on an existing identity in place — call this
/// wherever a device's label actually gets edited (`routes::device`'s
/// label form, `approve_join`'s `set_label` action), so a rename never
/// orphans the identity's accumulated fingerprint history.
pub async fn rename(store: &Store, iface: &str, id: &str, new_label: &str) {
    let mut records = read_registry(store, iface).await;
    if let Some(r) = records.iter_mut().find(|r| r.id == id) {
        if r.label != new_label {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            r.label_history.push((r.label.clone(), now_ts));
            r.label = new_label.to_string();
        }
        write_registry(store, iface, &records).await;
    }
}

/// Convenience wrapper for callers that only have a MAC, not an identity
/// id (i.e. every actual label-editing call site): looks up whether `mac`
/// belongs to a known identity in the registry, and if so, renames it. A
/// no-op for a MAC that was never registered — the common case, since
/// only randomized MACs ever get an entry at all.
pub async fn rename_if_known(store: &Store, iface: &str, mac: &str, new_label: &str) {
    let records = read_registry(store, iface).await;
    if let Some(r) = find_by_mac(&records, mac) {
        let id = r.id.clone();
        rename(store, iface, &id, new_label).await;
    }
}

/// Score in [0, 100]: how well `observed` matches an already-registered
/// `record`. Each signal only ever adds points when *both* sides actually
/// have it — missing data is "no signal", not a mismatch, so a device
/// that simply didn't send a vendor class isn't penalized for it.
///
/// Weights: mDNS name is the only signal likely to be unique enough on
/// its own to identify one physical device (so it alone still clears
/// `SUGGEST_THRESHOLD`); mDNS model and WiFi capabilities identify
/// device/chipset *class* (two units of the same phone model score
/// identically on both); DHCP vendor class and option-request order are
/// weaker still (OS/DHCP-client-version level). All five cap at 100.
fn score(observed: &Observed, record: &FingerprintRecord) -> u8 {
    if !record.evidence.is_empty() {
        let mut total = 0.0f32;
        for (signal, value, weight) in observed_signals(observed) {
            let best = record
                .evidence
                .iter()
                .filter(|item| item.signal == signal && item.value == value)
                .map(|item| {
                    let repeat_confidence = (item.observations.min(3) as f32) / 3.0;
                    let age_days = now_unix().saturating_sub(item.last_seen) as f32 / 86_400.0;
                    let recency = (1.0 - age_days / 365.0 * 0.5).max(0.5);
                    weight * (0.5 + repeat_confidence * 0.5) * recency
                })
                .fold(0.0f32, f32::max);
            total += best;
        }
        return total.min(100.0) as u8;
    }
    let mut total = 0u32;
    if !observed.mdns.name.is_empty() && observed.mdns.name.eq_ignore_ascii_case(&record.mdns_name)
    {
        total += 50;
    }
    if !observed.mdns.model.is_empty() && observed.mdns.model == record.mdns_model {
        total += 15;
    }
    if !observed.wifi_caps.is_empty() && observed.wifi_caps == record.wifi_caps {
        total += 15;
    }
    if !observed.dhcp.vendor_class.is_empty() && observed.dhcp.vendor_class == record.dhcp_vendor {
        total += 10;
    }
    if !observed.dhcp.requested_options.is_empty()
        && observed.dhcp.requested_options == record.dhcp_options
    {
        total += 10;
    }
    if !observed.browser_cookie.is_empty() && observed.browser_cookie == record.browser_cookie {
        total += 35;
    }
    if !observed.http_headers.is_empty() && observed.http_headers == record.http_headers {
        total += 10;
    }
    if !observed.tcp_syn.is_empty() && observed.tcp_syn == record.tcp_syn {
        total += 8;
    }
    if !observed.tls_clienthello.is_empty() && observed.tls_clienthello == record.tls_clienthello {
        total += 12;
    }
    if !observed.quic_initial.is_empty() && observed.quic_initial == record.quic_initial {
        total += 12;
    }
    total.min(100) as u8
}

/// A match worth showing the admin isn't a coin flip: require either the
/// mDNS name alone (the strongest single signal — a persistent name is
/// unlikely to collide between two different devices) or a combination of
/// at least two weaker signals.
const SUGGEST_THRESHOLD: u8 = 50;

/// Two candidates within this many points of each other are treated as
/// "can't honestly tell which" rather than confidently picking the higher
/// one — exactly the case (two similarly-fingerprinted devices, e.g. the
/// same phone model owned by two people in the house) where a single
/// confident-looking suggestion is least trustworthy.
const AMBIGUOUS_MARGIN: u8 = 10;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    None,
    /// One record clearly scores above the rest.
    Confident(FingerprintRecord, u8),
    /// Two or more records score within `AMBIGUOUS_MARGIN` of each other,
    /// highest first — showing just the top one would overstate how sure
    /// this actually is.
    Ambiguous(Vec<(FingerprintRecord, u8)>),
}

pub fn best_match(observed: &Observed, records: &[FingerprintRecord]) -> MatchResult {
    let mut scored: Vec<(FingerprintRecord, u8)> = records
        .iter()
        .map(|r| (r.clone(), score(observed, r)))
        .filter(|(_, s)| *s >= SUGGEST_THRESHOLD)
        .collect();
    scored.sort_by_key(|b| std::cmp::Reverse(b.1));

    match scored.first() {
        None => MatchResult::None,
        Some((_, top)) => {
            let top = *top;
            let tied: Vec<_> = scored
                .iter()
                .take_while(|(_, s)| top - *s <= AMBIGUOUS_MARGIN)
                .cloned()
                .collect();
            if tied.len() > 1 {
                MatchResult::Ambiguous(tied)
            } else {
                MatchResult::Confident(scored[0].0.clone(), top)
            }
        }
    }
}

/// Refreshes packet signals only on an already registered MAC. This is
/// intentionally not a create path: passive observation can improve a human
/// suggestion but can never silently establish an identity.
pub async fn ingest_packet(store: &Store, iface: &str, mac: &str, packet: &[u8], now_ts: u64) {
    let Some(signal) = crate::packet_observer::classify(packet) else {
        return;
    };
    let mut observed = Observed::default();
    if signal.starts_with("tcp;") {
        observed.tcp_syn = signal;
    } else if signal.starts_with("tls;") {
        observed.tls_clienthello = signal;
    } else {
        observed.quic_initial = signal;
    }
    let records = read_registry(store, iface).await;
    if let Some(record) = find_by_mac(&records, mac) {
        merge_into(store, iface, &record.id, mac, &observed, now_ts).await;
    }
}

/// Other registered identities that look like `target` — for the
/// identity detail page, to catch e.g. the same physical device having
/// been registered twice under different labels, or flag two genuinely
/// different devices that happen to share a fingerprint. A high score
/// here means "worth a human checking these aren't the same device," not
/// a claim that they are — same ceiling as `best_match`.
pub fn similar_identities(
    target: &FingerprintRecord,
    all: &[FingerprintRecord],
) -> Vec<(FingerprintRecord, u8)> {
    let observed = Observed {
        dhcp: DhcpFingerprint {
            requested_options: target.dhcp_options.clone(),
            vendor_class: target.dhcp_vendor.clone(),
        },
        wifi_caps: target.wifi_caps.clone(),
        mdns: MdnsInfo {
            name: target.mdns_name.clone(),
            model: target.mdns_model.clone(),
        },
        browser_cookie: target.browser_cookie.clone(),
        http_headers: target.http_headers.clone(),
        tcp_syn: target.tcp_syn.clone(),
        tls_clienthello: target.tls_clienthello.clone(),
        quic_initial: target.quic_initial.clone(),
    };
    let mut scored: Vec<(FingerprintRecord, u8)> = all
        .iter()
        .filter(|r| r.id != target.id)
        .map(|r| (r.clone(), score(&observed, r)))
        .filter(|(_, s)| *s >= SUGGEST_THRESHOLD)
        .collect();
    scored.sort_by_key(|b| std::cmp::Reverse(b.1));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::dhcp_fingerprint::DhcpFingerprint;
    use crate::data::mdns::MdnsInfo;

    fn rec(label: &str) -> FingerprintRecord {
        FingerprintRecord {
            id: "deadbeef".to_string(),
            label: label.to_string(),
            dhcp_options: "1,3,6".to_string(),
            dhcp_vendor: "android-dhcp-14".to_string(),
            wifi_caps: "ht,vht,wmm".to_string(),
            mdns_name: "Kirils-Phone".to_string(),
            mdns_model: "Pixel 8".to_string(),
            macs: vec!["02:aa:aa:aa:aa:aa".to_string()],
            last_seen: 1000,
            first_seen: 1000,
            label_history: Vec::new(),
            browser_cookie: String::new(),
            http_headers: String::new(),
            tcp_syn: String::new(),
            tls_clienthello: String::new(),
            quic_initial: String::new(),
            evidence: Vec::new(),
        }
    }

    fn full_observed() -> Observed {
        Observed {
            dhcp: DhcpFingerprint {
                requested_options: "1,3,6".into(),
                vendor_class: "android-dhcp-14".into(),
            },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo {
                name: "Kirils-Phone".into(),
                model: "Pixel 8".into(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn repeated_observations_accumulate_historical_evidence() {
        let observed = full_observed();
        let mut record = rec("phone");
        record_evidence(&mut record, &observed, 100);
        record_evidence(&mut record, &observed, 200);
        let mdns = record
            .evidence
            .iter()
            .find(|item| item.signal == "mdns_name")
            .unwrap();
        assert_eq!(mdns.observations, 2);
        assert_eq!(mdns.first_seen, 100);
        assert_eq!(mdns.last_seen, 200);
    }

    #[test]
    fn recent_evidence_outweighs_year_old_evidence() {
        let observed = full_observed();
        let now = now_unix();
        let mut recent = rec("recent");
        record_evidence(&mut recent, &observed, now);
        let mut old = rec("old");
        record_evidence(&mut old, &observed, now.saturating_sub(365 * 86_400));
        assert!(score(&observed, &recent) > score(&observed, &old));
    }

    #[test]
    fn changing_signal_history_is_bounded_per_signal() {
        let mut record = rec("phone");
        for n in 0..12 {
            let mut observed = Observed::default();
            observed.mdns.name = format!("phone-{n}");
            record_evidence(&mut record, &observed, n);
        }
        assert_eq!(
            record
                .evidence
                .iter()
                .filter(|item| item.signal == "mdns_name")
                .count(),
            8
        );
        assert!(!record.evidence.iter().any(|item| item.value == "phone-0"));
    }

    #[tokio::test]
    async fn create_registers_a_new_identity_with_a_generated_id() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils-Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;
        assert_eq!(id.len(), 8);

        let records = read_registry(&store, "guest").await;
        assert_eq!(records.len(), 1);
        let mut expected = rec("Kirils-Phone");
        expected.id = id;
        record_evidence(&mut expected, &full_observed(), 1000);
        assert_eq!(records[0], expected);
    }

    #[tokio::test]
    async fn merge_into_folds_a_rotated_mac_into_the_same_identity() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils-Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;

        // Second sighting under a rotated MAC, no fresh fingerprint data this time.
        merge_into(
            &store,
            "guest",
            &id,
            "02:bb:bb:bb:bb:bb",
            &Observed::default(),
            2000,
        )
        .await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].macs,
            vec!["02:aa:aa:aa:aa:aa", "02:bb:bb:bb:bb:bb"]
        );
        assert_eq!(records[0].last_seen, 2000);
        // Fingerprint fields weren't wiped by the empty second observation.
        assert_eq!(records[0].mdns_name, "Kirils-Phone");
        assert_eq!(records[0].wifi_caps, "ht,vht,wmm");
        // The label is untouched by merge_into — renaming is a separate action.
        assert_eq!(records[0].label, "Kirils-Phone");
    }

    #[tokio::test]
    async fn rename_updates_the_label_without_touching_history() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;
        merge_into(
            &store,
            "guest",
            &id,
            "02:bb:bb:bb:bb:bb",
            &Observed::default(),
            2000,
        )
        .await;

        rename(&store, "guest", &id, "Kiril's iPhone 16").await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "Kiril's iPhone 16");
        // History survives the rename intact.
        assert_eq!(
            records[0].macs,
            vec!["02:aa:aa:aa:aa:aa", "02:bb:bb:bb:bb:bb"]
        );
        assert_eq!(records[0].mdns_name, "Kirils-Phone");
    }

    #[tokio::test]
    async fn rename_records_the_outgoing_label_in_history() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;

        rename(&store, "guest", &id, "Kiril's iPhone 16").await;
        rename(&store, "guest", &id, "Kiril's Phone (old)").await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records[0].label, "Kiril's Phone (old)");
        let labels: Vec<_> = records[0]
            .label_history
            .iter()
            .map(|(l, _)| l.as_str())
            .collect();
        assert_eq!(labels, vec!["Kirils Phone", "Kiril's iPhone 16"]);
    }

    #[tokio::test]
    async fn renaming_to_the_same_label_does_not_add_a_history_entry() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;

        rename(&store, "guest", &id, "Kirils Phone").await;

        let records = read_registry(&store, "guest").await;
        assert!(records[0].label_history.is_empty());
    }

    #[tokio::test]
    async fn first_seen_is_set_once_and_never_changed_afterward() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;
        merge_into(
            &store,
            "guest",
            &id,
            "02:bb:bb:bb:bb:bb",
            &Observed::default(),
            5000,
        )
        .await;
        rename(&store, "guest", &id, "New Name").await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records[0].first_seen, 1000);
        assert_eq!(records[0].last_seen, 5000);
    }

    #[test]
    fn similar_identities_finds_a_matching_other_record_and_excludes_the_target() {
        let target = rec("Kirils-Phone");
        let mut similar = rec("Bobs-Phone");
        similar.id = "cafef00d".to_string();
        let mut unrelated = rec("Office-Printer");
        unrelated.id = "12345678".to_string();
        unrelated.mdns_name = "Office-Printer".to_string();
        unrelated.mdns_model = "LaserJet".to_string();
        unrelated.dhcp_options = "1,121".to_string();
        unrelated.dhcp_vendor = "".to_string();
        unrelated.wifi_caps = "".to_string();

        let all = vec![target.clone(), similar.clone(), unrelated];
        let results = similar_identities(&target, &all);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.id, "cafef00d");
    }

    #[test]
    fn similar_identities_is_empty_when_nothing_else_matches() {
        let target = rec("Kirils-Phone");
        let mut unrelated = rec("Office-Printer");
        unrelated.id = "12345678".to_string();
        unrelated.mdns_name = String::new();
        unrelated.mdns_model = String::new();
        unrelated.dhcp_options = "1,121".to_string();
        unrelated.dhcp_vendor = "MSFT 5.0".to_string();
        unrelated.wifi_caps = "he".to_string();

        assert!(similar_identities(&target, &[target.clone(), unrelated]).is_empty());
    }

    #[tokio::test]
    async fn reusing_a_label_for_an_unconfirmed_new_device_creates_a_separate_identity() {
        // Two genuinely different devices that happen to get the same
        // label text — without an explicit confirmed match, `create`
        // must never merge them into one record.
        let store = Store::open_in_memory().unwrap();
        let id_a = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;
        let id_b = create(
            &store,
            "guest",
            "Kirils Phone",
            "02:cc:cc:cc:cc:cc",
            &full_observed(),
            2000,
        )
        .await;

        assert_ne!(id_a, id_b);
        let records = read_registry(&store, "guest").await;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records.iter().filter(|r| r.label == "Kirils Phone").count(),
            2
        );
    }

    #[tokio::test]
    async fn find_by_mac_locates_the_identity_a_mac_belongs_to() {
        let store = Store::open_in_memory().unwrap();
        let id = create(
            &store,
            "guest",
            "Kirils-Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;
        merge_into(
            &store,
            "guest",
            &id,
            "02:bb:bb:bb:bb:bb",
            &Observed::default(),
            2000,
        )
        .await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(
            find_by_mac(&records, "02:BB:BB:BB:BB:BB").map(|r| r.id.as_str()),
            Some(id.as_str())
        );
        assert!(find_by_mac(&records, "02:ff:ff:ff:ff:ff").is_none());
    }

    #[tokio::test]
    async fn rename_if_known_renames_the_identity_owning_that_mac() {
        let store = Store::open_in_memory().unwrap();
        create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;

        rename_if_known(&store, "guest", "02:aa:aa:aa:aa:aa", "Kiril's iPhone 16").await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records[0].label, "Kiril's iPhone 16");
    }

    #[tokio::test]
    async fn rename_if_known_is_a_no_op_for_an_unregistered_mac() {
        let store = Store::open_in_memory().unwrap();
        create(
            &store,
            "guest",
            "Kirils Phone",
            "02:aa:aa:aa:aa:aa",
            &full_observed(),
            1000,
        )
        .await;

        rename_if_known(&store, "guest", "00:11:22:33:44:55", "Some Other Name").await;

        let records = read_registry(&store, "guest").await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "Kirils Phone");
    }

    #[test]
    fn mdns_name_match_alone_clears_the_suggestion_threshold() {
        let observed = Observed {
            dhcp: DhcpFingerprint::default(),
            wifi_caps: String::new(),
            mdns: MdnsInfo {
                name: "Kirils-Phone".into(),
                model: String::new(),
            },
            ..Default::default()
        };
        match best_match(&observed, &[rec("Kirils-Phone")]) {
            MatchResult::Confident(matched, s) => {
                assert_eq!(matched.label, "Kirils-Phone");
                assert!(s >= SUGGEST_THRESHOLD);
            }
            other => panic!("expected a confident match, got {other:?}"),
        }
    }

    #[test]
    fn dhcp_and_wifi_caps_signals_alone_do_not_clear_the_threshold() {
        // Same DHCP fingerprint + WiFi capability class, but that's not
        // enough on its own to claim it's the *same physical device* —
        // any unit of the same phone model scores identically on both.
        let observed = Observed {
            dhcp: DhcpFingerprint {
                requested_options: "1,3,6".into(),
                vendor_class: "android-dhcp-14".into(),
            },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo::default(),
            ..Default::default()
        };
        assert_eq!(
            best_match(&observed, &[rec("Kirils-Phone")]),
            MatchResult::None
        );
    }

    #[test]
    fn no_signal_in_common_never_matches() {
        let observed = Observed {
            dhcp: DhcpFingerprint {
                requested_options: "1,121".into(),
                vendor_class: "MSFT 5.0".into(),
            },
            wifi_caps: "he".into(),
            mdns: MdnsInfo {
                name: "Some-Other-Device".into(),
                model: "iPhone16,2".into(),
            },
            ..Default::default()
        };
        assert_eq!(
            best_match(&observed, &[rec("Kirils-Phone")]),
            MatchResult::None
        );
    }

    #[test]
    fn best_match_picks_the_highest_scoring_record() {
        let mut weak = rec("Weak-Match");
        weak.mdns_name = String::new(); // no name signal at all

        let strong = rec("Strong-Match"); // has the mDNS name

        match best_match(&full_observed(), &[weak, strong]) {
            MatchResult::Confident(matched, _) => assert_eq!(matched.label, "Strong-Match"),
            other => panic!("expected a confident match, got {other:?}"),
        }
    }

    #[test]
    fn two_similarly_scored_records_are_reported_as_ambiguous() {
        // Two different identities that both happen to be the same phone
        // model with no mDNS name from either — exactly the case where a
        // single confident-looking guess would be dishonest.
        let mut device_a = rec("Alices-Phone");
        device_a.mdns_name = String::new();
        let mut device_b = rec("Bobs-Phone");
        device_b.mdns_name = String::new();

        let observed = Observed {
            dhcp: DhcpFingerprint {
                requested_options: "1,3,6".into(),
                vendor_class: "android-dhcp-14".into(),
            },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo {
                name: String::new(),
                model: "Pixel 8".into(),
            },
            ..Default::default()
        };
        match best_match(&observed, &[device_a, device_b]) {
            MatchResult::Ambiguous(candidates) => {
                assert_eq!(candidates.len(), 2);
                let labels: Vec<_> = candidates.iter().map(|(r, _)| r.label.as_str()).collect();
                assert!(labels.contains(&"Alices-Phone"));
                assert!(labels.contains(&"Bobs-Phone"));
            }
            other => panic!("expected an ambiguous match, got {other:?}"),
        }
    }

    #[test]
    fn a_clear_winner_is_not_reported_as_ambiguous() {
        let weak = {
            let mut r = rec("Weak-Match");
            r.mdns_name = String::new();
            r.wifi_caps = String::new();
            r
        };
        let strong = rec("Strong-Match");
        match best_match(&full_observed(), &[weak, strong]) {
            MatchResult::Confident(matched, _) => assert_eq!(matched.label, "Strong-Match"),
            other => panic!("expected a confident match, got {other:?}"),
        }
    }
}
