//! What a stance (allow/deny/ask) is actually about.

use crate::canonical::CanonicalEncode;

/// Fixed discriminant order — never reorder existing variants, only ever
/// append new ones with new tag numbers, or every existing signature
/// becomes unverifiable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TargetSelector {
    Domain(String),
    DomainSuffix(String),
    Ip(String),
    Cidr(String),
    Service(String),
    /// A target further scoped to a specific protocol/port — orthogonal to
    /// which of the above it wraps, e.g. "example.com on tcp/443 only".
    ProtoPort {
        inner: Box<TargetSelector>,
        proto: String,
        port: u32,
    },
}

impl TargetSelector {
    /// Stable string form for SQLite storage/indexing — `(kind, value)`.
    pub fn kind_str(&self) -> &'static str {
        match self {
            TargetSelector::Domain(_) => "domain",
            TargetSelector::DomainSuffix(_) => "domain_suffix",
            TargetSelector::Ip(_) => "ip",
            TargetSelector::Cidr(_) => "cidr",
            TargetSelector::Service(_) => "service",
            TargetSelector::ProtoPort { .. } => "proto_port",
        }
    }
}

impl CanonicalEncode for TargetSelector {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        match self {
            TargetSelector::Domain(s) => {
                out.push(0);
                s.canonical_encode(out);
            }
            TargetSelector::DomainSuffix(s) => {
                out.push(1);
                s.canonical_encode(out);
            }
            TargetSelector::Ip(s) => {
                out.push(2);
                s.canonical_encode(out);
            }
            TargetSelector::Cidr(s) => {
                out.push(3);
                s.canonical_encode(out);
            }
            TargetSelector::Service(s) => {
                out.push(4);
                s.canonical_encode(out);
            }
            TargetSelector::ProtoPort { inner, proto, port } => {
                out.push(5);
                inner.canonical_encode(out);
                proto.canonical_encode(out);
                port.canonical_encode(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::encode;

    #[test]
    fn domain_and_domain_suffix_encode_differently() {
        let a = encode(&TargetSelector::Domain("example.com".into()));
        let b = encode(&TargetSelector::DomainSuffix("example.com".into()));
        assert_ne!(
            a, b,
            "different variants with the same string must not collide"
        );
    }

    #[test]
    fn kind_str_is_stable() {
        assert_eq!(TargetSelector::Domain("x".into()).kind_str(), "domain");
        assert_eq!(TargetSelector::Cidr("10.0.0.0/8".into()).kind_str(), "cidr");
    }
}
