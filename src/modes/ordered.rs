//! Canal **ordenado** ratcheado entre dos partes (`CryptoNugget`) con acumulador SHA-256 de integridad.
//!
//! Mejoras de seguridad v0.4:
//! - Validación estricta `packet.sequence == self.rx_seq` antes de descifrar (mitiga desincronización de contador).
//! - Soporte de transición de `epoch` para cualquier época `N -> N + 1` (corrige el bug que bloqueaba el canal tras el segundo snapshot).
//! - Limpieza con `zeroize` del buffer descifrado cuando falla la conversión UTF-8 (mitiga CWE-226).
//! - **SHA-256 Transcript Accumulator (`tx_transcript_hash` / `rx_transcript_hash`)**: Cada paquete cifrado y descifrado
//!   actualiza un hash rodante SHA-256 `H_n = SHA256(H_{n-1} || seq || nonce || tag)` que permite a ambos extremos
//!   auditar en tiempo constante que ningún paquete ni contexto intermedio fue omitido o alterado.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::packet::{
    FLAG_AAD_PRESENT, NONCE_LEN, Packet, TAG_LEN, WIRE_VERSION_V1, WIRE_VERSION_V2,
    build_internal_aad_v1, build_internal_aad_v2_with_epoch,
};
use crate::seed::MasterSeed;

const DEFAULT_CONTEXT: &[u8] = b"cryptonugget:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoNugget {
    pub(crate) tx_key: [u8; 32],
    pub(crate) rx_key: [u8; 32],
    pub(crate) tx_seq: u64,
    pub(crate) rx_seq: u64,
    pub(crate) epoch: u64,
    /// Hash acumulativo SHA-256 de todos los mensajes emitidos (prueba de integridad de contexto).
    pub(crate) tx_transcript_hash: [u8; 32],
    /// Hash acumulativo SHA-256 de todos los mensajes recibidos.
    pub(crate) rx_transcript_hash: [u8; 32],
    pub(crate) context: Vec<u8>,
    pub(crate) requires_resume_ack: bool,
}

impl std::fmt::Debug for CryptoNugget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoNugget")
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .field("tx_seq", &self.tx_seq)
            .field("rx_seq", &self.rx_seq)
            .field("epoch", &self.epoch)
            .field("requires_resume_ack", &self.requires_resume_ack)
            .finish()
    }
}

impl CryptoNugget {
    pub fn builder(seed: &MasterSeed, role: Role) -> crate::Builder<'_> {
        crate::Builder::new(seed, role, DEFAULT_CONTEXT)
    }

    pub fn builder_with_context<'a>(
        seed: &'a MasterSeed,
        role: Role,
        context: &'a [u8],
    ) -> crate::Builder<'a> {
        crate::Builder::new(seed, role, context)
    }

    pub fn new(seed: &MasterSeed, role: Role) -> Self {
        Self::new_with_context(seed, role, DEFAULT_CONTEXT)
    }

    pub fn new_with_context(seed: &MasterSeed, role: Role, context: &[u8]) -> Self {
        let mut salt = b"CryptoNugget:seed:v1".to_vec();
        salt.push(0);
        salt.extend_from_slice(context);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), seed.as_bytes());
        let mut clave_a = [0u8; 32];
        let mut clave_b = [0u8; 32];
        let mut init_hash_a = [0u8; 32];
        let mut init_hash_b = [0u8; 32];

        hkdf.expand(b"tx-key:a", &mut clave_a).unwrap();
        hkdf.expand(b"tx-key:b", &mut clave_b).unwrap();
        hkdf.expand(b"transcript:a", &mut init_hash_a).unwrap();
        hkdf.expand(b"transcript:b", &mut init_hash_b).unwrap();

        let (tx, rx, tx_hash, rx_hash) = match role {
            Role::Initiator => (clave_a, clave_b, init_hash_a, init_hash_b),
            Role::Responder => (clave_b, clave_a, init_hash_b, init_hash_a),
        };

        CryptoNugget {
            tx_key: tx,
            rx_key: rx,
            tx_seq: 0,
            rx_seq: 0,
            epoch: 0,
            tx_transcript_hash: tx_hash,
            rx_transcript_hash: rx_hash,
            context: context.to_vec(),
            requires_resume_ack: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted_state(
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        tx_seq: u64,
        rx_seq: u64,
        epoch: u64,
        tx_transcript_hash: [u8; 32],
        rx_transcript_hash: [u8; 32],
        context: Vec<u8>,
    ) -> Self {
        Self {
            tx_key,
            rx_key,
            tx_seq,
            rx_seq,
            epoch,
            tx_transcript_hash,
            rx_transcript_hash,
            context,
            requires_resume_ack: true,
        }
    }

    pub fn cifrar(&mut self, texto_plano: &str) -> Result<String, Error> {
        self.cifrar_bytes(texto_plano.as_bytes())
    }

    pub fn cifrar_bytes(&mut self, plaintext: &[u8]) -> Result<String, Error> {
        let packet = self.cifrar_bytes_with_aad(plaintext, b"")?;
        Ok(packet.to_base64())
    }

    pub fn cifrar_bytes_with_aad(
        &mut self,
        plaintext: &[u8],
        user_aad: &[u8],
    ) -> Result<Packet, Error> {
        if self.requires_resume_ack {
            return Err(Error::EstadoSinReanudar);
        }
        let next_seq = self.tx_seq.checked_add(1).ok_or(Error::Cifrado)?;

        let key = Key::<Aes256Gcm>::from_slice(&self.tx_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let sequence = self.tx_seq;

        let flags = if user_aad.is_empty() {
            0u8
        } else {
            FLAG_AAD_PRESENT
        };
        let internal_aad = build_internal_aad_v2_with_epoch(flags, sequence, user_aad, self.epoch)?;

        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: plaintext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_ga.as_slice());

        // Actualizar SHA-256 de integración del flujo de salida
        Self::update_transcript(
            &mut self.tx_transcript_hash,
            self.epoch,
            sequence,
            &nonce,
            &ciphertext,
        );

        self.mutar_clave(true);
        self.tx_seq = next_seq;

        Ok(Packet {
            version: WIRE_VERSION_V2,
            flags,
            node_id: 0,
            epoch: self.epoch,
            sequence,
            timestamp_ms: 0,
            nonce,
            ciphertext,
        })
    }

    /// Descifra y convierte a UTF-8 limpiando la memoria (`zeroize`) si los bytes no son UTF-8 válido.
    pub fn descifrar(&mut self, paquete_base64: &str) -> Result<String, Error> {
        let bytes = self.descifrar_bytes(paquete_base64)?;
        String::from_utf8(bytes).map_err(|err| {
            let mut raw = err.into_bytes();
            raw.zeroize();
            Error::Utf8
        })
    }

    pub fn descifrar_bytes(&mut self, paquete_base64: &str) -> Result<Vec<u8>, Error> {
        let packet = Packet::from_base64(paquete_base64)?;
        self.descifrar_bytes_with_aad(&packet, b"")
    }

    pub fn descifrar_bytes_with_aad(
        &mut self,
        packet: &Packet,
        user_aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.requires_resume_ack {
            return Err(Error::EstadoSinReanudar);
        }
        // Verificación estricta de secuencia esperada antes de tocar AES-GCM
        if packet.sequence != self.rx_seq {
            return Err(Error::Autenticacion);
        }
        let next_rx_seq = self.rx_seq.checked_add(1).ok_or(Error::Autenticacion)?;

        // Soportar transición de epoch N -> N+1 en cualquier época (corrige bug donde solo funcionaba en epoch == 0)
        let epoch_candidates: [u64; 2] = [self.epoch, self.epoch.saturating_add(1)];

        let nonce = Nonce::from_slice(&packet.nonce);
        let key = Key::<Aes256Gcm>::from_slice(&self.rx_key);
        let cipher = Aes256Gcm::new(key);

        let mut authenticated_epoch = self.epoch;
        let plaintext = match packet.version {
            WIRE_VERSION_V2 => {
                let mut opened_msg = None;
                for &candidate in &epoch_candidates {
                    let internal_aad = build_internal_aad_v2_with_epoch(
                        packet.flags,
                        packet.sequence,
                        user_aad,
                        candidate,
                    )?;
                    if let Ok(opened) = cipher.decrypt(
                        nonce,
                        Payload {
                            msg: &packet.ciphertext,
                            aad: &internal_aad,
                        },
                    ) {
                        authenticated_epoch = candidate;
                        opened_msg = Some(opened);
                        break;
                    }
                }
                opened_msg.ok_or(Error::Autenticacion)?
            }
            WIRE_VERSION_V1 => {
                if !user_aad.is_empty() {
                    return Err(Error::Autenticacion);
                }
                let internal_aad = build_internal_aad_v1(packet.sequence);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &packet.ciphertext,
                            aad: &internal_aad,
                        },
                    )
                    .map_err(|_| Error::Autenticacion)?
            }
            other => return Err(Error::VersionNoSoportada(other)),
        };

        // Actualizar SHA-256 de integración del flujo de entrada
        Self::update_transcript(
            &mut self.rx_transcript_hash,
            authenticated_epoch,
            packet.sequence,
            &packet.nonce,
            &packet.ciphertext,
        );

        self.mutar_clave(false);
        self.rx_seq = next_rx_seq;
        self.epoch = authenticated_epoch;

        Ok(plaintext)
    }

    /// Actualiza el acumulador SHA-256 encadenando el estado anterior con la secuencia, nonce y tag GCM.
    fn update_transcript(
        acc: &mut [u8; 32],
        epoch: u64,
        seq: u64,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) {
        let mut hasher = Sha256::new();
        hasher.update(b"CryptoNugget:Transcript:v1");
        hasher.update(*acc);
        hasher.update(epoch.to_be_bytes());
        hasher.update(seq.to_be_bytes());
        hasher.update(nonce);
        // Enlazamos el tag de autenticación GCM (últimos 16 bytes) que ya resume criptográficamente el ciphertext + AAD
        let tag_start = ciphertext.len().saturating_sub(TAG_LEN);
        hasher.update(&ciphertext[tag_start..]);
        let digest = hasher.finalize();
        acc.copy_from_slice(&digest);
    }

    /// Devuelve el hash SHA-256 acumulativo de transmisión y recepción `(tx_sha256, rx_sha256)`.
    /// Si `alice.transcript_hashes().0 == bob.transcript_hashes().1`, está matemáticamente probado
    /// que Bob recibió exactamente el mismo contexto que Alice emitió sin 1 solo bit perdido.
    pub fn transcript_hashes(&self) -> ([u8; 32], [u8; 32]) {
        (self.tx_transcript_hash, self.rx_transcript_hash)
    }

    fn mutar_clave(&mut self, es_tx: bool) {
        let clave_actual = if es_tx { &self.tx_key } else { &self.rx_key };

        let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:ratchet:v1"), clave_actual);
        let mut nueva_clave = [0u8; 32];
        hkdf.expand(b"ratchet-key:v1", &mut nueva_clave)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");

        if es_tx {
            self.tx_key.zeroize();
            self.tx_key.copy_from_slice(&nueva_clave);
        } else {
            self.rx_key.zeroize();
            self.rx_key.copy_from_slice(&nueva_clave);
        }
        nueva_clave.zeroize();
    }

    pub fn obtener_estado_adn(&self) -> String {
        let tx_fp = fingerprint(&self.tx_key, b"fp:tx");
        let rx_fp = fingerprint(&self.rx_key, b"fp:rx");
        format!(
            "TX:{:02X}{:02X}{:02X}{:02X} RX:{:02X}{:02X}{:02X}{:02X} SEQ:{}/{} SHA:{:02X}{:02X}",
            tx_fp[0],
            tx_fp[1],
            tx_fp[2],
            tx_fp[3],
            rx_fp[0],
            rx_fp[1],
            rx_fp[2],
            rx_fp[3],
            self.tx_seq,
            self.rx_seq,
            self.tx_transcript_hash[0],
            self.rx_transcript_hash[0]
        )
    }

    pub fn generar_semilla_maestra() -> MasterSeed {
        MasterSeed::generate()
    }

    pub fn generar_enlace_invitacion(seed: &MasterSeed) -> String {
        format!(
            "nugget://sincronizar?v=1&semilla={}",
            seed.export_for_transfer()
        )
    }

    pub fn extraer_semilla_de_enlace(enlace: &str) -> Result<MasterSeed, Error> {
        if let Some(semilla) = enlace.strip_prefix("nugget://sincronizar?v=1&semilla=") {
            MasterSeed::from_transfer_token(semilla).map_err(|_| Error::EnlaceInvalido)
        } else {
            Err(Error::EnlaceInvalido)
        }
    }
}

fn fingerprint(key: &[u8; 32], info: &[u8]) -> [u8; 4] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:fingerprint:v1"), key);
    let mut out = [0u8; 4];
    hkdf.expand(info, &mut out)
        .expect("HKDF expand nunca falla con SHA256 y 4 bytes");
    out
}
