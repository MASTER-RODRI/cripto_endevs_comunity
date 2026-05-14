//! `ReplayWindowChannel`: canal con ventana anti-replay y entrega fuera de orden.
//!
//! Importante: este modo usa claves estables por dirección y NO ofrece el
//! forward secrecy incremental del canal ordenado ratcheado. Es opt-in para
//! transportes que pueden entregar mensajes fuera de orden.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::packet::{FLAG_AAD_PRESENT, NONCE_LEN, WIRE_VERSION_V2, build_internal_aad_v2};
use crate::{Error, MasterSeed, Packet, Role};

const DEFAULT_CONTEXT: &[u8] = b"cryptonugget:v1";
const MAX_WINDOW: u64 = 128;

/// Canal con ventana anti-replay.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReplayWindowChannel {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_seq: u64,
    highest_seen: Option<u64>,
    seen_bitmap: u128,
    window: u64,
}

impl std::fmt::Debug for ReplayWindowChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayWindowChannel")
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .field("tx_seq", &self.tx_seq)
            .field("highest_seen", &self.highest_seen)
            .field("window", &self.window)
            .finish()
    }
}

impl ReplayWindowChannel {
    /// Inicializa con contexto por defecto.
    pub fn new(seed: &MasterSeed, role: Role, window: u64) -> Result<Self, Error> {
        Self::new_with_context(seed, role, DEFAULT_CONTEXT, window)
    }

    /// Inicializa con contexto explícito y ventana anti-replay.
    pub fn new_with_context(
        seed: &MasterSeed,
        role: Role,
        context: &[u8],
        window: u64,
    ) -> Result<Self, Error> {
        if window == 0 || window > MAX_WINDOW {
            return Err(Error::ModoInvalido);
        }

        let mut salt = b"CryptoNugget:replay-window:v1".to_vec();
        salt.push(0);
        salt.extend_from_slice(context);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), seed.as_bytes());
        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        hkdf.expand(b"window-key:a", &mut key_a)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        hkdf.expand(b"window-key:b", &mut key_b)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        let (tx_key, rx_key) = match role {
            Role::Initiator => (key_a, key_b),
            Role::Responder => (key_b, key_a),
        };

        Ok(Self {
            tx_key,
            rx_key,
            tx_seq: 0,
            highest_seen: None,
            seen_bitmap: 0,
            window,
        })
    }

    /// Cifra un mensaje dentro del canal con ventana anti-replay.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Packet, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.tx_key));
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_ga.as_slice());
        let sequence = self.tx_seq;
        let flags = if aad.is_empty() { 0 } else { FLAG_AAD_PRESENT };
        let internal_aad = build_internal_aad_v2(flags, sequence, aad);
        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: plaintext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;
        self.tx_seq = self.tx_seq.checked_add(1).ok_or(Error::Cifrado)?;
        Ok(Packet {
            version: WIRE_VERSION_V2,
            flags,
            sequence,
            nonce,
            ciphertext,
        })
    }

    /// Abre un paquete, aceptando entrega fuera de orden dentro de la ventana.
    pub fn open(&mut self, packet: &Packet, aad: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.version != WIRE_VERSION_V2 {
            return Err(Error::VersionNoSoportada(packet.version));
        }
        self.ensure_sequence_is_new(packet.sequence)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.rx_key));
        let nonce = Nonce::from_slice(&packet.nonce);
        let internal_aad = build_internal_aad_v2(packet.flags, packet.sequence, aad);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &packet.ciphertext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        self.mark_seen(packet.sequence);
        Ok(plaintext)
    }

    fn ensure_sequence_is_new(&self, sequence: u64) -> Result<(), Error> {
        let Some(highest) = self.highest_seen else {
            return Ok(());
        };

        if sequence > highest {
            return Ok(());
        }

        let delta = highest - sequence;
        if delta >= self.window {
            return Err(Error::FueraDeOrden);
        }
        if (self.seen_bitmap & (1u128 << delta)) != 0 {
            return Err(Error::Repetido);
        }
        Ok(())
    }

    fn mark_seen(&mut self, sequence: u64) {
        match self.highest_seen {
            None => {
                self.highest_seen = Some(sequence);
                self.seen_bitmap = 1;
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.seen_bitmap = if shift >= 128 {
                    1
                } else {
                    (self.seen_bitmap << shift) | 1
                };
                let mask = if self.window == 128 {
                    u128::MAX
                } else {
                    (1u128 << self.window) - 1
                };
                self.seen_bitmap &= mask;
                self.highest_seen = Some(sequence);
            }
            Some(highest) => {
                let delta = highest - sequence;
                self.seen_bitmap |= 1u128 << delta;
            }
        }
    }
}
