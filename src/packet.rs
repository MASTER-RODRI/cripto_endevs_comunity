//! Formato binario de paquete (`Packet` v1, v2 y v3 distribuido/temporal) determinista
//! e idéntico en todos los lenguajes (Big-Endian / Network Byte Order).
//!
//! Layout binario Wire v3 (42 bytes de cabecera fija + ciphertext + tag de 16 bytes):
//! ```text
//! Offset  Longitud  Campo
//! 0       1         version = 3 (u8)
//! 1       1         flags (u8: bit 0 = AAD presente, bit 1 = SHA-256 encadenado)
//! 2..6    4         node_id (u32 Big-Endian) -> Identifica la instancia (Web, Back, Worker)
//! 6..14   8         epoch (u64 Big-Endian)   -> Época de arranque/reinicio (Crash-Recovery)
//! 14..22  8         sequence (u64 Big-Endian)-> Secuencia atómica por mensaje
//! 22..30  8         timestamp_ms (u64 BE)    -> Tiempo UTC en milisegundos sellado en AEAD
//! 30..42  12        nonce (96 bits)          -> Nonce determinista derivado por HKDF
//! 42..    N + 16    ciphertext + GCM Tag     -> Payload cifrado + Tag de 128 bits
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::error::Error;

pub const WIRE_VERSION_V3: u8 = 3;
pub const WIRE_VERSION_V2: u8 = 2;
pub const WIRE_VERSION_V1: u8 = 1;

pub const FLAG_AAD_PRESENT: u8 = 0x01;
pub const FLAG_INTEGRITY_HASH_BOUND: u8 = 0x02;

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

pub const V3_HEADER_LEN: usize = 1 + 1 + 4 + 8 + 8 + 8 + NONCE_LEN; // 42 bytes
pub const V2_HEADER_LEN: usize = 1 + 1 + 8 + NONCE_LEN; // 22 bytes
pub const V1_HEADER_LEN: usize = 1 + 8 + NONCE_LEN; // 21 bytes

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub version: u8,
    pub flags: u8,
    pub node_id: u32,
    pub epoch: u64,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Packet {
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
            WIRE_VERSION_V3 => {
                let mut out = Vec::with_capacity(V3_HEADER_LEN + self.ciphertext.len());
                out.push(WIRE_VERSION_V3);
                out.push(self.flags);
                out.extend_from_slice(&self.node_id.to_be_bytes());
                out.extend_from_slice(&self.epoch.to_be_bytes());
                out.extend_from_slice(&self.sequence.to_be_bytes());
                out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
                out.extend_from_slice(&self.nonce);
                out.extend_from_slice(&self.ciphertext);
                out
            }
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < V1_HEADER_LEN + TAG_LEN {
            return Err(Error::PaqueteCorrupto);
        }
        let version = bytes[0];
        match version {
            WIRE_VERSION_V3 => {
                if bytes.len() < V3_HEADER_LEN + TAG_LEN {
                    return Err(Error::PaqueteCorrupto);
                }
                let flags = bytes[1];
                let node_id = u32::from_be_bytes(
                    bytes[2..6].try_into().map_err(|_| Error::PaqueteCorrupto)?,
                );
                let epoch = u64::from_be_bytes(
                    bytes[6..14].try_into().map_err(|_| Error::PaqueteCorrupto)?,
                );
                let sequence = u64::from_be_bytes(
                    bytes[14..22].try_into().map_err(|_| Error::PaqueteCorrupto)?,
                );
                let timestamp_ms = u64::from_be_bytes(
                    bytes[22..30].try_into().map_err(|_| Error::PaqueteCorrupto)?,
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&bytes[30..V3_HEADER_LEN]);
                let ciphertext = bytes[V3_HEADER_LEN..].to_vec();
                Ok(Packet {
                    version,
                    flags,
                    node_id,
                    epoch,
                    sequence,
                    timestamp_ms,
                    nonce,
                    ciphertext,
                })
            }
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
                    node_id: 0,
                    epoch: 0,
                    sequence,
                    timestamp_ms: 0,
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
                    node_id: 0,
                    epoch: 0,
                    sequence,
                    timestamp_ms: 0,
                    nonce,
                    ciphertext,
                })
            }
            other => Err(Error::VersionNoSoportada(other)),
        }
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, Error> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| Error::Base64(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

pub(crate) fn build_internal_aad_v2(
    flags: u8,
    sequence: u64,
    user_aad: &[u8],
) -> Result<Vec<u8>, Error> {
    build_internal_aad_v2_with_epoch(flags, sequence, user_aad, 0)
}

pub(crate) fn build_internal_aad_v2_with_epoch(
    flags: u8,
    sequence: u64,
    user_aad: &[u8],
    epoch: u64,
) -> Result<Vec<u8>, Error> {
    let aad_len_u32 = u32::try_from(user_aad.len()).map_err(|_| Error::AadDemasiadoLargo)?;
    let mut aad = Vec::with_capacity(1 + 1 + 8 + 13 + 4 + user_aad.len());
    aad.push(WIRE_VERSION_V2);
    aad.push(flags);
    aad.extend_from_slice(&sequence.to_be_bytes());
    if epoch != 0 {
        aad.extend_from_slice(b"epoch");
        aad.extend_from_slice(&epoch.to_be_bytes());
    }
    if flags & FLAG_AAD_PRESENT != 0 {
        aad.extend_from_slice(&aad_len_u32.to_be_bytes());
        aad.extend_from_slice(user_aad);
    }
    Ok(aad)
}

pub(crate) fn build_internal_aad_v3(
    flags: u8,
    node_id: u32,
    epoch: u64,
    sequence: u64,
    timestamp_ms: u64,
    context_hash: &[u8; 32],
    user_aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad_len_u32 = u32::try_from(user_aad.len()).map_err(|_| Error::AadDemasiadoLargo)?;
    let mut aad = Vec::with_capacity(1 + 1 + 4 + 8 + 8 + 8 + 32 + 4 + user_aad.len());
    aad.push(WIRE_VERSION_V3);
    aad.push(flags);
    aad.extend_from_slice(&node_id.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&timestamp_ms.to_be_bytes());
    aad.extend_from_slice(context_hash);
    if flags & FLAG_AAD_PRESENT != 0 {
        aad.extend_from_slice(&aad_len_u32.to_be_bytes());
        aad.extend_from_slice(user_aad);
    }
    Ok(aad)
}

pub(crate) fn build_internal_aad_v1(sequence: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = WIRE_VERSION_V1;
    aad[1..].copy_from_slice(&sequence.to_be_bytes());
    aad
}
