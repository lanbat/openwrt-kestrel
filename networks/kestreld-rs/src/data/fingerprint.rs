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

/// The fingerprint signals gathered for one specific, not-yet-identified
/// join — nothing here is tied to a label yet.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub dhcp: DhcpFingerprint,
    pub mdns: MdnsInfo,
    pub wifi_caps: String,
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
        let mdns = crate::data::mdns::lookup_device_info(bridge_ip, ip).await.unwrap_or_default();
        let wifi_caps = crate::data::wifi_caps::capabilities(net, mac).await;
        Self { dhcp, mdns, wifi_caps }
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
}

const FIELDS: usize = 11;

/// `label_history` entries are encoded as `label@timestamp`, joined by
/// `|` — labels are free text (see the "allow any text as device label"
/// history in this project), so a label containing a literal `@` or `|`
/// would confuse this encoding. Same trust level as the rest of this
/// project's tab-separated file formats (a device-labels entry with a
/// literal tab would break the same way): fine for a home router admin's
/// own input, not hardened against adversarial label text.
fn encode_label_history(history: &[(String, u64)]) -> String {
    history.iter().map(|(label, ts)| format!("{label}@{ts}")).collect::<Vec<_>>().join("|")
}

fn parse_label_history(s: &str) -> Vec<(String, u64)> {
    s.split('|')
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (label, ts) = e.rsplit_once('@')?;
            Some((label.to_string(), ts.parse().unwrap_or(0)))
        })
        .collect()
}

pub async fn read_registry(path: &Path) -> Vec<FingerprintRecord> {
    files::read_lines(path)
        .await
        .iter()
        .filter_map(|line| parse_record(line))
        .collect()
}

/// The identity `mac` currently belongs to, if any — used both to offer a
/// suggestion and to find what needs renaming when a device's label is
/// edited.
pub fn find_by_mac<'a>(records: &'a [FingerprintRecord], mac: &str) -> Option<&'a FingerprintRecord> {
    let mac = mac.to_lowercase();
    records.iter().find(|r| r.macs.contains(&mac))
}

fn parse_record(line: &str) -> Option<FingerprintRecord> {
    let f: Vec<&str> = line.splitn(FIELDS, '\t').collect();
    if f.len() < FIELDS || f[0].is_empty() || f[1].is_empty() {
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
        macs: f[7].split(',').map(str::to_lowercase).filter(|s| !s.is_empty()).collect(),
        last_seen: f[8].parse().unwrap_or(0),
        first_seen: f[9].parse().unwrap_or(0),
        label_history: parse_label_history(f[10]),
    })
}

fn format_record(r: &FingerprintRecord) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        r.id, r.label, r.dhcp_options, r.dhcp_vendor, r.wifi_caps, r.mdns_name, r.mdns_model,
        r.macs.join(","), r.last_seen, r.first_seen, encode_label_history(&r.label_history),
    )
}

async fn write_registry(path: &Path, records: &[FingerprintRecord]) {
    let content = records.iter().map(format_record).collect::<Vec<_>>().join("\n");
    let content = if content.is_empty() { content } else { format!("{content}\n") };
    let _ = tokio::fs::write(path, content).await;
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
    r.last_seen = now_ts;
}

/// Registers a brand-new identity (no confirmed match existed) for
/// `label`, seeded with whatever was observed for `mac`. Returns the
/// generated id.
pub async fn create(path: &Path, label: &str, mac: &str, observed: &Observed, now_ts: u64) -> String {
    let mut records = read_registry(path).await;
    let id = gen_id().await;
    let mac = mac.to_lowercase();
    records.push(FingerprintRecord {
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
    });
    write_registry(path, &records).await;
    id
}

/// Confirmed-match path: folds `mac` into the *existing* identity `id`,
/// refreshing whichever fingerprint fields were actually captured this
/// time (an empty `Observed` field never overwrites a previously-known
/// one). Does not touch the label — that's `rename`'s job, kept separate
/// so a label edit later doesn't require re-confirming a match.
pub async fn merge_into(path: &Path, id: &str, mac: &str, observed: &Observed, now_ts: u64) {
    let mut records = read_registry(path).await;
    let mac = mac.to_lowercase();
    if let Some(r) = records.iter_mut().find(|r| r.id == id) {
        apply_observed(r, &mac, observed, now_ts);
        write_registry(path, &records).await;
    }
}

/// Updates the label on an existing identity in place — call this
/// wherever a device's label actually gets edited (`routes::device`'s
/// label form, `approve_join`'s `set_label` action), so a rename never
/// orphans the identity's accumulated fingerprint history.
pub async fn rename(path: &Path, id: &str, new_label: &str) {
    let mut records = read_registry(path).await;
    if let Some(r) = records.iter_mut().find(|r| r.id == id) {
        if r.label != new_label {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            r.label_history.push((r.label.clone(), now_ts));
            r.label = new_label.to_string();
        }
        write_registry(path, &records).await;
    }
}

/// Convenience wrapper for callers that only have a MAC, not an identity
/// id (i.e. every actual label-editing call site): looks up whether `mac`
/// belongs to a known identity in the registry at `path` and, if so,
/// renames it. A no-op for a MAC that was never registered — the common
/// case, since only randomized MACs ever get an entry at all.
pub async fn rename_if_known(path: &Path, mac: &str, new_label: &str) {
    let records = read_registry(path).await;
    if let Some(r) = find_by_mac(&records, mac) {
        let id = r.id.clone();
        rename(path, &id, new_label).await;
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
    let mut total = 0u32;
    if !observed.mdns.name.is_empty() && observed.mdns.name.eq_ignore_ascii_case(&record.mdns_name) {
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
    if !observed.dhcp.requested_options.is_empty() && observed.dhcp.requested_options == record.dhcp_options {
        total += 10;
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
    scored.sort_by(|a, b| b.1.cmp(&a.1));

    match scored.first() {
        None => MatchResult::None,
        Some((_, top)) => {
            let top = *top;
            let tied: Vec<_> = scored.iter().take_while(|(_, s)| top - *s <= AMBIGUOUS_MARGIN).cloned().collect();
            if tied.len() > 1 {
                MatchResult::Ambiguous(tied)
            } else {
                MatchResult::Confident(scored[0].0.clone(), top)
            }
        }
    }
}

/// Other registered identities that look like `target` — for the
/// identity detail page, to catch e.g. the same physical device having
/// been registered twice under different labels, or flag two genuinely
/// different devices that happen to share a fingerprint. A high score
/// here means "worth a human checking these aren't the same device," not
/// a claim that they are — same ceiling as `best_match`.
pub fn similar_identities(target: &FingerprintRecord, all: &[FingerprintRecord]) -> Vec<(FingerprintRecord, u8)> {
    let observed = Observed {
        dhcp: DhcpFingerprint {
            requested_options: target.dhcp_options.clone(),
            vendor_class: target.dhcp_vendor.clone(),
        },
        wifi_caps: target.wifi_caps.clone(),
        mdns: MdnsInfo { name: target.mdns_name.clone(), model: target.mdns_model.clone() },
    };
    let mut scored: Vec<(FingerprintRecord, u8)> = all
        .iter()
        .filter(|r| r.id != target.id)
        .map(|r| (r.clone(), score(&observed, r)))
        .filter(|(_, s)| *s >= SUGGEST_THRESHOLD)
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1));
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
        }
    }

    fn full_observed() -> Observed {
        Observed {
            dhcp: DhcpFingerprint { requested_options: "1,3,6".into(), vendor_class: "android-dhcp-14".into() },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo { name: "Kirils-Phone".into(), model: "Pixel 8".into() },
        }
    }

    #[tokio::test]
    async fn create_registers_a_new_identity_with_a_generated_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils-Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;
        assert_eq!(id.len(), 8);

        let records = read_registry(&path).await;
        assert_eq!(records.len(), 1);
        let mut expected = rec("Kirils-Phone");
        expected.id = id;
        assert_eq!(records[0], expected);
    }

    #[tokio::test]
    async fn merge_into_folds_a_rotated_mac_into_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils-Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;

        // Second sighting under a rotated MAC, no fresh fingerprint data this time.
        merge_into(&path, &id, "02:bb:bb:bb:bb:bb", &Observed::default(), 2000).await;

        let records = read_registry(&path).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].macs, vec!["02:aa:aa:aa:aa:aa", "02:bb:bb:bb:bb:bb"]);
        assert_eq!(records[0].last_seen, 2000);
        // Fingerprint fields weren't wiped by the empty second observation.
        assert_eq!(records[0].mdns_name, "Kirils-Phone");
        assert_eq!(records[0].wifi_caps, "ht,vht,wmm");
        // The label is untouched by merge_into — renaming is a separate action.
        assert_eq!(records[0].label, "Kirils-Phone");
    }

    #[tokio::test]
    async fn rename_updates_the_label_without_touching_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;
        merge_into(&path, &id, "02:bb:bb:bb:bb:bb", &Observed::default(), 2000).await;

        rename(&path, &id, "Kiril's iPhone 16").await;

        let records = read_registry(&path).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "Kiril's iPhone 16");
        // History survives the rename intact.
        assert_eq!(records[0].macs, vec!["02:aa:aa:aa:aa:aa", "02:bb:bb:bb:bb:bb"]);
        assert_eq!(records[0].mdns_name, "Kirils-Phone");
    }

    #[tokio::test]
    async fn rename_records_the_outgoing_label_in_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;

        rename(&path, &id, "Kiril's iPhone 16").await;
        rename(&path, &id, "Kiril's Phone (old)").await;

        let records = read_registry(&path).await;
        assert_eq!(records[0].label, "Kiril's Phone (old)");
        let labels: Vec<_> = records[0].label_history.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, vec!["Kirils Phone", "Kiril's iPhone 16"]);
    }

    #[tokio::test]
    async fn renaming_to_the_same_label_does_not_add_a_history_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;

        rename(&path, &id, "Kirils Phone").await;

        let records = read_registry(&path).await;
        assert!(records[0].label_history.is_empty());
    }

    #[tokio::test]
    async fn first_seen_is_set_once_and_never_changed_afterward() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;
        merge_into(&path, &id, "02:bb:bb:bb:bb:bb", &Observed::default(), 5000).await;
        rename(&path, &id, "New Name").await;

        let records = read_registry(&path).await;
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id_a = create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;
        let id_b = create(&path, "Kirils Phone", "02:cc:cc:cc:cc:cc", &full_observed(), 2000).await;

        assert_ne!(id_a, id_b);
        let records = read_registry(&path).await;
        assert_eq!(records.len(), 2);
        assert_eq!(records.iter().filter(|r| r.label == "Kirils Phone").count(), 2);
    }

    #[tokio::test]
    async fn find_by_mac_locates_the_identity_a_mac_belongs_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        let id = create(&path, "Kirils-Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;
        merge_into(&path, &id, "02:bb:bb:bb:bb:bb", &Observed::default(), 2000).await;

        let records = read_registry(&path).await;
        assert_eq!(find_by_mac(&records, "02:BB:BB:BB:BB:BB").map(|r| r.id.as_str()), Some(id.as_str()));
        assert!(find_by_mac(&records, "02:ff:ff:ff:ff:ff").is_none());
    }

    #[tokio::test]
    async fn rename_if_known_renames_the_identity_owning_that_mac() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;

        rename_if_known(&path, "02:aa:aa:aa:aa:aa", "Kiril's iPhone 16").await;

        let records = read_registry(&path).await;
        assert_eq!(records[0].label, "Kiril's iPhone 16");
    }

    #[tokio::test]
    async fn rename_if_known_is_a_no_op_for_an_unregistered_mac() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp");
        create(&path, "Kirils Phone", "02:aa:aa:aa:aa:aa", &full_observed(), 1000).await;

        rename_if_known(&path, "00:11:22:33:44:55", "Some Other Name").await;

        let records = read_registry(&path).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "Kirils Phone");
    }

    #[test]
    fn mdns_name_match_alone_clears_the_suggestion_threshold() {
        let observed = Observed {
            dhcp: DhcpFingerprint::default(),
            wifi_caps: String::new(),
            mdns: MdnsInfo { name: "Kirils-Phone".into(), model: String::new() },
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
            dhcp: DhcpFingerprint { requested_options: "1,3,6".into(), vendor_class: "android-dhcp-14".into() },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo::default(),
        };
        assert_eq!(best_match(&observed, &[rec("Kirils-Phone")]), MatchResult::None);
    }

    #[test]
    fn no_signal_in_common_never_matches() {
        let observed = Observed {
            dhcp: DhcpFingerprint { requested_options: "1,121".into(), vendor_class: "MSFT 5.0".into() },
            wifi_caps: "he".into(),
            mdns: MdnsInfo { name: "Some-Other-Device".into(), model: "iPhone16,2".into() },
        };
        assert_eq!(best_match(&observed, &[rec("Kirils-Phone")]), MatchResult::None);
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
            dhcp: DhcpFingerprint { requested_options: "1,3,6".into(), vendor_class: "android-dhcp-14".into() },
            wifi_caps: "ht,vht,wmm".into(),
            mdns: MdnsInfo { name: String::new(), model: "Pixel 8".into() },
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
