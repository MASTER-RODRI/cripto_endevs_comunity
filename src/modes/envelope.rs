//! `StatelessEnvelope`: cifrado autenticado sin estado de sesión.
//!
//! Cada mensaje deriva una subclave desde `MasterSeed`, `context` y nonce. No
//! hay ratchet, contador ni protección anti-replay interna: este modo es para
//! blobs/eventos independientes donde el llamador provee deduplicación si la
//! necesita.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::packet::{FLAG_AAD_PRESENT, NONCE_LEN, WIRE_VERSION_V2, build_internal_aad_v2};
use crate::{Error, MasterSeed, Packet};

const DEFAULT_CONTEXT: &[u8] = b"cryptonugget:v1";

/// Sobre stateless para payloads independientes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StatelessEnvelope {
    root_key: [u8; 32],
}

impl std::fmt::Debug for StatelessEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatelessEnvelope")
            .field("root_key", &"<redacted>")
            .finish()
    }
}

impl StatelessEnvelope {
    /// Inicializa con el contexto por defecto.
    pub fn new(seed: &MasterSeed) -> Self {
        Self::new_with_context(seed, DEFAULT_CONTEXT)
    }

    /// Inicializa con separación de dominio por aplicación/protocolo.
    pub fn new_with_context(seed: &MasterSeed, context: &[u8]) -> Self {
        let mut salt = b"CryptoNugget:envelope:v1".to_vec();
        salt.push(0);
        salt.extend_from_slice(context);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), seed.as_bytes());
        let mut root_key = [0u8; 32];
        hkdf.expand(b"stateless-envelope-root", &mut root_key)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        Self { root_key }
    }

    /// Cifra un payload independiente y devuelve un `Packet` v2.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Packet, Error> {
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_ga.as_slice());
        let mut key_bytes = self.derive_message_key(&nonce);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();
        let flags = if aad.is_empty() { 0 } else { FLAG_AAD_PRESENT };
        let internal_aad = build_internal_aad_v2(flags, 0, aad);
        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: plaintext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;

        Ok(Packet {
            version: WIRE_VERSION_V2,
            flags,
            sequence: 0,
            nonce,
            ciphertext,
        })
    }

    /// Abre un payload independiente.
    pub fn open(&self, packet: &Packet, aad: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.version != WIRE_VERSION_V2 {
            return Err(Error::VersionNoSoportada(packet.version));
        }
        let mut key_bytes = self.derive_message_key(&packet.nonce);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();
        let nonce = Nonce::from_slice(&packet.nonce);
        let internal_aad = build_internal_aad_v2(packet.flags, packet.sequence, aad);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &packet.ciphertext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Autenticacion)
    }

    fn derive_message_key(&self, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:envelope:message:v1"), &self.root_key);
        let mut key = [0u8; 32];
        hkdf.expand(nonce, &mut key)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        key
    }
}
