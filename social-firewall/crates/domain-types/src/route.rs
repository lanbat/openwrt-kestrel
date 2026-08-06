use crate::canonical::CanonicalEncode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouteProfile {
    pub name: String,
    pub table: u32,
    pub interface: String,
    pub enabled: bool,
    pub vpn: bool,
}

impl LocalRouteProfile {
    pub fn config_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.name.canonical_encode(&mut out);
        self.table.canonical_encode(&mut out);
        self.interface.canonical_encode(&mut out);
        self.enabled.canonical_encode(&mut out);
        self.vpn.canonical_encode(&mut out);
        out
    }
}
