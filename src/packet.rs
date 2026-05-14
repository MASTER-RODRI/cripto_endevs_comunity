//! Wire-format `Packet` (v2) + binary/base64 codecs + v1 inbound decode.
//!
//! Wire v2 layout (outbound default starting v0.3):
//!
//! ```text
//!   version(1) ‖ flags(1) ‖ sequence(8 BE) ‖ nonce(12) ‖ ciphertext+tag
//! ```
//!
//! `flags` bit 0: AAD present in the AEAD computation. The wire packet itself
//! does NOT carry the user-supplied AAD bytes — only whether AAD was bound.
//! The receiver MUST supply the same AAD via [`crate::CryptoNugget::descifrar_bytes_with_aad`].
//!
//! Wire v1 (legacy, inbound-only for one release cycle, accepted on
//! `OrderedChannel` only):
//!
//! ```text
//!   version(1)=1 ‖ sequence(8 BE) ‖ nonce(12) ‖ ciphertext+tag
//! ```
//!
//! `Packet::from_bytes` accepts both v1 and v2 and normalises them into a
//! v2-shaped `Packet` value (v1 becomes `version=1, flags=0`, which the
//! channel then routes through the v1-AAD path).
//!
//! Unknown versions are rejected with [`Error::VersionNoSoportada`].

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::error::Error;

/// Current outbound wire version.
pub const WIRE_VERSION_V2: u8 = 2;
/// Legacy inbound wire version (accepted one release cycle on `OrderedChannel`).
pub const WIRE_VERSION_V1: u8 = 1;

/// Bit 0 of `flags`: user AAD was bound into the AEAD AAD.
pub const FLAG_AAD_PRESENT: u8 = 0x01;

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

/// v2 header = version(1) + flags(1) + seq(8) + nonce(12) = 22 bytes.
pub(crate) const V2_HEADER_LEN: usize = 1 + 1 + 8 + NONCE_LEN;
/// v1 header = version(1) + seq(8) + nonce(12) = 21 bytes.
pub(crate) const V1_HEADER_LEN: usize = 1 + 8 + NONCE_LEN;

/// Typed wire-format packet.
///
/// `Packet` is the canonical serialised form of one encrypted message. It is
/// public so that callers can:
///
/// - Pin a packet on disk / queue / network in deterministic binary form via
///   [`Packet::to_bytes`] / [`Packet::from_bytes`].
/// - Transport packets through text-only channels (chat, JSON, URLs) via
///   [`Packet::to_base64`] / [`Packet::from_base64`].
/// - Inspect the version and flags (e.g. for telemetry) without re-decoding.
///
/// `Packet` carries no key material and no plaintext. It is safe to log the
/// `version`, `flags`, and `sequence` fields; the `nonce` and `ciphertext` are
/// not secret per se but together they uniquely identify the message and
/// should be treated as PII-equivalent metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Wire-format version. v0.3 emits `2`; accepts `1` for legacy peers.
    pub version: u8,
    /// Bit-packed flags. Bit 0 = AAD bound (see [`FLAG_AAD_PRESENT`]).
    pub flags: u8,
    /// Per-message sequence number, authenticated via AAD.
    pub sequence: u64,
    /// 96-bit AES-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext concatenated with the 128-bit GCM tag.
    pub ciphertext: Vec<u8>,
}

impl Packet {
    /// Serialise this packet to its v2 binary wire form.
    ///
    /// v1 inbound packets that were normalised into a `Packet` re-encode in
    /// v1 shape (no `flags` byte) so that the bytes round-trip exactly.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.version {
            WIRE_VERSION_V1 => {
                let mut out = Vec::with_capacity(V1_HEADER_LEN + self.ciphertext.len());
                out.push(WIRE_VERSION_V1);
                out.extend_from_slice(&self.sequence.to_be_bytes());
                out.extend_from_slice(&self.nonce);
                out.extend_from_slice(&self.ciphertext);
                out
            }
            // v2-shaped layout for current and future packet versions. Future
            // versions keep their explicit byte so decoders can reject them as
            // `VersionNoSoportada` instead of silently downgrading to v2.
            _ => {
                let mut out = Vec::with_capacity(V2_HEADER_LEN + self.ciphertext.len());
                out.push(self.version);
                out.push(self.flags);
                out.extend_from_slice(&self.sequence.to_be_bytes());
                out.extend_from_slice(&self.nonce);
                out.extend_from_slice(&self.ciphertext);
                out
            }
        }
    }

    /// Parse a `Packet` from raw wire bytes.
    ///
    /// Accepts both v2 and v1 layouts. Unknown versions return
    /// [`Error::VersionNoSoportada`]. Truncated buffers return
    /// [`Error::PaqueteCorrupto`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < V1_HEADER_LEN + TAG_LEN {
            return Err(Error::PaqueteCorrupto);
        }
        let version = bytes[0];
        match version {
            WIRE_VERSION_V2 => {
                if bytes.len() < V2_HEADER_LEN + TAG_LEN {
                    return Err(Error::PaqueteCorrupto);
                }
                let flags = bytes[1];
                let sequence = u64::from_be_bytes(
                    bytes[2..10]
                        .try_into()
                        .map_err(|_| Error::PaqueteCorrupto)?,
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&bytes[10..V2_HEADER_LEN]);
                let ciphertext = bytes[V2_HEADER_LEN..].to_vec();
                Ok(Packet {
                    version,
                    flags,
                    sequence,
                    nonce,
                    ciphertext,
                })
            }
            WIRE_VERSION_V1 => {
                if bytes.len() < V1_HEADER_LEN + TAG_LEN {
                    return Err(Error::PaqueteCorrupto);
                }
                let sequence =
                    u64::from_be_bytes(bytes[1..9].try_into().map_err(|_| Error::PaqueteCorrupto)?);
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&bytes[9..V1_HEADER_LEN]);
                let ciphertext = bytes[V1_HEADER_LEN..].to_vec();
                Ok(Packet {
                    version,
                    flags: 0,
                    sequence,
                    nonce,
                    ciphertext,
                })
            }
            other => Err(Error::VersionNoSoportada(other)),
        }
    }

    /// Encode this packet as standard base64.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    /// Decode a packet from a standard base64 string.
    pub fn from_base64(s: &str) -> Result<Self, Error> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| Error::Base64(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Build the AEAD AAD bound into the ciphertext.
///
/// v2 layout: `version‖flags‖seq‖[len(u32 BE)‖user_aad if flags bit 0 set]`.
/// The length prefix removes canonicalisation ambiguity; an empty user AAD
/// MUST keep `flags` bit 0 clear so empty-AAD packets are byte-identical to
/// the no-AAD path.
pub(crate) fn build_internal_aad_v2(flags: u8, sequence: u64, user_aad: &[u8]) -> Vec<u8> {
    build_internal_aad_v2_with_epoch(flags, sequence, user_aad, 0)
}

pub(crate) fn build_internal_aad_v2_with_epoch(
    flags: u8,
    sequence: u64,
    user_aad: &[u8],
    epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 1 + 8 + 4 + user_aad.len());
    aad.push(WIRE_VERSION_V2);
    aad.push(flags);
    aad.extend_from_slice(&sequence.to_be_bytes());
    if epoch != 0 {
        aad.extend_from_slice(b"epoch");
        aad.extend_from_slice(&epoch.to_be_bytes());
    }
    if flags & FLAG_AAD_PRESENT != 0 {
        let len = user_aad.len() as u32;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(user_aad);
    }
    aad
}

/// v1 AAD shape (legacy inbound only): `version(1)=1‖seq(8 BE)`.
pub(crate) fn build_internal_aad_v1(sequence: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = WIRE_VERSION_V1;
    aad[1..].copy_from_slice(&sequence.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_v2_no_user_aad_is_just_header() {
        let aad = build_internal_aad_v2(0, 7, b"");
        assert_eq!(aad, vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    }

    #[test]
    fn aad_v2_with_user_aad_includes_length_prefix() {
        let aad = build_internal_aad_v2(FLAG_AAD_PRESENT, 1, b"abc");
        // 2,1, seq=0..0..1, len=0,0,0,3, "abc"
        assert_eq!(
            aad,
            vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, b'a', b'b', b'c']
        );
    }

    #[test]
    fn aad_v1_is_version_plus_seq() {
        let aad = build_internal_aad_v1(42);
        assert_eq!(aad, [1, 0, 0, 0, 0, 0, 0, 0, 42]);
    }

    #[test]
    fn packet_v2_roundtrip_through_bytes() {
        let p = Packet {
            version: 2,
            flags: 1,
            sequence: 0xDEAD_BEEF,
            nonce: [9u8; 12],
            ciphertext: vec![0xAA; 32],
        };
        let bytes = p.to_bytes();
        let back = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn packet_v1_roundtrip_through_bytes() {
        let p = Packet {
            version: 1,
            flags: 0,
            sequence: 5,
            nonce: [3u8; 12],
            ciphertext: vec![0x55; 24],
        };
        let bytes = p.to_bytes();
        // v1 has no flags byte, so total length is V1_HEADER_LEN + ciphertext
        assert_eq!(bytes.len(), V1_HEADER_LEN + 24);
        let back = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn packet_future_version_preserves_version_byte_when_serialized() {
        let p = Packet {
            version: 9,
            flags: 0,
            sequence: 0,
            nonce: [0u8; 12],
            ciphertext: vec![0xAA; 16],
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes[0], 9);
        assert!(matches!(
            Packet::from_bytes(&bytes),
            Err(Error::VersionNoSoportada(9))
        ));
    }
}
