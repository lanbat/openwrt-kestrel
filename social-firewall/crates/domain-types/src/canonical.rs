//! Deterministic, byte-exact encoding for anything that gets hashed or
//! signed. Deliberately hand-rolled rather than `serde` + a general-purpose
//! format: signatures need the *exact same bytes* to reproduce on every
//! implementation, forever, and a derive macro's field order/representation
//! is an implementation detail that can silently change across versions of
//! a serialization crate. This trait is the one place that determinism is
//! guaranteed by construction, not by convention.
//!
//! Encoding rules (fixed, never to change without a new format version):
//! - Fixed-width integers: big-endian, explicit width.
//! - Byte strings: u32 big-endian length prefix, then raw bytes.
//! - `Option<T>`: one tag byte (0 = None, 1 = Some), then the value if Some.
//! - `Vec<T>`: u32 length prefix, then each element in order.
//! - Enums: one u8 discriminant, then that variant's fields in the fixed
//!   order documented on the enum itself — never inferred from declaration
//!   order by a macro.

pub trait CanonicalEncode {
    fn canonical_encode(&self, out: &mut Vec<u8>);
}

pub fn encode<T: CanonicalEncode>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.canonical_encode(&mut out);
    out
}

impl CanonicalEncode for u8 {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl CanonicalEncode for u32 {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl CanonicalEncode for u64 {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl CanonicalEncode for i64 {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl CanonicalEncode for bool {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.push(if *self { 1 } else { 0 });
    }
}

impl CanonicalEncode for str {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        let bytes = self.as_bytes();
        (bytes.len() as u32).canonical_encode(out);
        out.extend_from_slice(bytes);
    }
}

impl CanonicalEncode for String {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        self.as_str().canonical_encode(out);
    }
}

impl<T: CanonicalEncode> CanonicalEncode for Option<T> {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.canonical_encode(out);
            }
        }
    }
}

impl<T: CanonicalEncode> CanonicalEncode for Vec<T> {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        (self.len() as u32).canonical_encode(out);
        for item in self {
            item.canonical_encode(out);
        }
    }
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn canonical_encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_encodes_big_endian_fixed_width() {
        assert_eq!(encode(&1u64), vec![0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn string_is_length_prefixed() {
        let out = encode(&"hi".to_string());
        assert_eq!(out, vec![0, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn option_none_is_single_zero_byte() {
        assert_eq!(encode(&Option::<u64>::None), vec![0]);
    }

    #[test]
    fn option_some_is_tag_then_value() {
        let out = encode(&Some(1u64));
        assert_eq!(out[0], 1);
        assert_eq!(&out[1..], &1u64.to_be_bytes());
    }

    #[test]
    fn vec_is_length_prefixed_then_elements() {
        let out = encode(&vec![1u64, 2u64]);
        assert_eq!(out.len(), 4 + 8 + 8);
        assert_eq!(&out[0..4], &2u32.to_be_bytes());
    }

    #[test]
    fn encoding_is_deterministic_across_calls() {
        let a = encode(&vec!["a".to_string(), "b".to_string()]);
        let b = encode(&vec!["a".to_string(), "b".to_string()]);
        assert_eq!(a, b);
    }
}
