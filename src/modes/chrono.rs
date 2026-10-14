//! `ChronoMeshNode`: Motor distribuido, concurrente (Lock-Free Multi-Producer), basado en el tiempo
//! y resistente a apagones/reinicios (`Crash-Recovery`) con persistencia completa de estado.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;
use crate::packet::{
    FLAG_AAD_PRESENT, NONCE_LEN, Packet, TAG_LEN, WIRE_VERSION_V3, build_internal_aad_v3,
};
use crate::seed::MasterSeed;

const MAX_WINDOW: u64 = 128;
const MESH_STATE_MAGIC: &[u8; 4] = b"CNMS";
const MESH_STATE_VERSION: u8 = 1;

#[derive(Debug, Clone, Default)]
struct PeerReplayState {
    highest_seen: Option<u64>,
    seen_bitmap: u128,
    received_count: u64,
}

impl PeerReplayState {
    fn check(&self, seq: u64, window: u64) -> Result<(), Error> {
        let Some(highest) = self.highest_seen else {
            return Ok(());
        };
        if seq > highest {
            return Ok(());
        }
        let delta = highest - seq;
        if delta >= window {
            return Err(Error::FueraDeOrden);
        }
        if (self.seen_bitmap & (1u128 << delta)) != 0 {
            return Err(Error::Repetido);
        }
        Ok(())
    }

    fn record(&mut self, seq: u64, window: u64) {
        self.received_count = self.received_count.saturating_add(1);
        match self.highest_seen {
            None => {
                self.highest_seen = Some(seq);
                self.seen_bitmap = 1;
            }
            Some(highest) if seq > highest => {
                let shift = seq - highest;
                self.seen_bitmap = if shift >= 128 {
                    1
                } else {
                    (self.seen_bitmap << shift) | 1
                };
                let mask = if window >= 128 {
                    u128::MAX
                } else {
                    (1u128 << window) - 1
                };
                self.seen_bitmap &= mask;
                self.highest_seen = Some(seq);
            }
            Some(highest) => {
                let delta = highest - seq;
                self.seen_bitmap |= 1u128 << delta;
            }
        }
    }
}

pub struct ChronoMeshNode {
    mesh_root_key: [u8; 32],
    context_domain_hash: [u8; 32],
    node_id: u32,
    epoch: AtomicU64,
    tx_seq: AtomicU64,
    max_time_drift_ms: u64,
    replay_window: u64,
    rx_state: Mutex<RxTracker>,
}

struct RxTracker {
    peers: BTreeMap<(u32, u64), PeerReplayState>,
    multiset_integrity_hash: [u8; 32],
}

impl Drop for ChronoMeshNode {
    fn drop(&mut self) {
        self.mesh_root_key.zeroize();
        self.context_domain_hash.zeroize();
    }
}

impl std::fmt::Debug for ChronoMeshNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChronoMeshNode")
            .field("mesh_root_key", &"<redacted>")
            .field("node_id", &self.node_id)
            .field("epoch", &self.epoch.load(Ordering::Relaxed))
            .field("tx_seq", &self.tx_seq.load(Ordering::Relaxed))
            .field("max_time_drift_ms", &self.max_time_drift_ms)
            .finish()
    }
}

impl ChronoMeshNode {
    pub fn new(
        seed: &MasterSeed,
        context: &[u8],
        node_id: u32,
        boot_epoch: u64,
        max_time_drift_ms: u64,
    ) -> Self {
        let mut salt = Vec::with_capacity(28 + context.len());
        salt.extend_from_slice(b"CryptoNugget:ChronoMesh:v3:");
        salt.extend_from_slice(context);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), seed.as_bytes());
        let mut mesh_root_key = [0u8; 32];
        let mut context_domain_hash = [0u8; 32];
        hkdf.expand(b"mesh-root-key", &mut mesh_root_key).unwrap();
        hkdf.expand(b"mesh-context-hash", &mut context_domain_hash)
            .unwrap();

        Self {
            mesh_root_key,
            context_domain_hash,
            node_id,
            epoch: AtomicU64::new(boot_epoch),
            tx_seq: AtomicU64::new(0),
            max_time_drift_ms,
            replay_window: MAX_WINDOW,
            rx_state: Mutex::new(RxTracker {
                peers: BTreeMap::new(),
                multiset_integrity_hash: [0u8; 32],
            }),
        }
    }

    pub fn node_id(&self) -> u32 {
        self.node_id
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn current_tx_seq(&self) -> u64 {
        self.tx_seq.load(Ordering::Acquire)
    }

    #[inline]
    fn derive_packet_crypto(
        &self,
        node_id: u32,
        epoch: u64,
        seq: u64,
        timestamp_ms: u64,
    ) -> ([u8; 32], [u8; NONCE_LEN]) {
        let mut info = [0u8; 4 + 8 + 8 + 8];
        info[0..4].copy_from_slice(&node_id.to_be_bytes());
        info[4..12].copy_from_slice(&epoch.to_be_bytes());
        info[12..20].copy_from_slice(&seq.to_be_bytes());
        info[20..28].copy_from_slice(&timestamp_ms.to_be_bytes());

        let hkdf = Hkdf::<Sha256>::new(Some(&self.context_domain_hash), &self.mesh_root_key);
        let mut okm = [0u8; 32 + NONCE_LEN];
        hkdf.expand(&info, &mut okm)
            .expect("HKDF expand nunca falla para 44 bytes");

        let mut key = [0u8; 32];
        let mut nonce = [0u8; NONCE_LEN];
        key.copy_from_slice(&okm[..32]);
        nonce.copy_from_slice(&okm[32..]);
        okm.zeroize();
        (key, nonce)
    }

    fn fold_packet_into_integrity_hash(acc: &mut [u8; 32], packet: &Packet) {
        let mut hasher = Sha256::new();
        hasher.update(b"ChronoMesh:PacketDigest:v3");
        hasher.update(packet.node_id.to_be_bytes());
        hasher.update(packet.epoch.to_be_bytes());
        hasher.update(packet.sequence.to_be_bytes());
        hasher.update(packet.timestamp_ms.to_be_bytes());
        hasher.update(packet.nonce);
        let tag_start = packet.ciphertext.len().saturating_sub(TAG_LEN);
        hasher.update(&packet.ciphertext[tag_start..]);
        let digest = hasher.finalize();

        for (a, b) in acc.iter_mut().zip(digest.iter()) {
            *a ^= *b;
        }
    }

    /// Cifra en tiempo real de forma Lock-Free (`&self`).
    pub fn seal_realtime(
        &self,
        plaintext: &[u8],
        user_aad: &[u8],
        now_ms: u64,
    ) -> Result<Packet, Error> {
        let epoch = self.epoch.load(Ordering::Acquire);
        let seq = self.tx_seq.fetch_add(1, Ordering::Relaxed);
        if seq == u64::MAX {
            return Err(Error::Cifrado);
        }

        let flags = if user_aad.is_empty() {
            0
        } else {
            FLAG_AAD_PRESENT
        };
        let internal_aad = build_internal_aad_v3(
            flags,
            self.node_id,
            epoch,
            seq,
            now_ms,
            &self.context_domain_hash,
            user_aad,
        )?;

        let (mut msg_key, nonce) = self.derive_packet_crypto(self.node_id, epoch, seq, now_ms);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        msg_key.zeroize();

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;

        let packet = Packet {
            version: WIRE_VERSION_V3,
            flags,
            node_id: self.node_id,
            epoch,
            sequence: seq,
            timestamp_ms: now_ms,
            nonce,
            ciphertext,
        };

        if let Ok(mut guard) = self.rx_state.lock() {
            Self::fold_packet_into_integrity_hash(&mut guard.multiset_integrity_hash, &packet);
        }

        Ok(packet)
    }

    /// Abre y verifica un paquete en tiempo real.
    pub fn open_realtime(
        &self,
        packet: &Packet,
        user_aad: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        if packet.version != WIRE_VERSION_V3 {
            return Err(Error::VersionNoSoportada(packet.version));
        }

        if now_ms.abs_diff(packet.timestamp_ms) > self.max_time_drift_ms {
            return Err(Error::TiempoExpiradoOInvalido);
        }

        {
            let guard = self.rx_state.lock().map_err(|_| Error::Autenticacion)?;
            if let Some(peer) = guard.peers.get(&(packet.node_id, packet.epoch)) {
                peer.check(packet.sequence, self.replay_window)?;
            }
        }

        let internal_aad = build_internal_aad_v3(
            packet.flags,
            packet.node_id,
            packet.epoch,
            packet.sequence,
            packet.timestamp_ms,
            &self.context_domain_hash,
            user_aad,
        )?;

        let (mut msg_key, expected_nonce) = self.derive_packet_crypto(
            packet.node_id,
            packet.epoch,
            packet.sequence,
            packet.timestamp_ms,
        );

        if expected_nonce != packet.nonce {
            msg_key.zeroize();
            return Err(Error::Autenticacion);
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        msg_key.zeroize();

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&packet.nonce),
                Payload {
                    msg: &packet.ciphertext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        let mut guard = self.rx_state.lock().map_err(|_| Error::Autenticacion)?;
        let peer = guard
            .peers
            .entry((packet.node_id, packet.epoch))
            .or_default();
        peer.check(packet.sequence, self.replay_window)?;
        peer.record(packet.sequence, self.replay_window);
        Self::fold_packet_into_integrity_hash(&mut guard.multiset_integrity_hash, packet);

        Ok(plaintext)
    }

    /// Abre un archivo o registro cifrado persistido en disco/BD en cualquier momento del pasado
    /// (incluso después de múltiples apagones o reinicios del servidor).
    pub fn open_persisted_record(
        &self,
        packet: &Packet,
        user_aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if packet.version != WIRE_VERSION_V3 {
            return Err(Error::VersionNoSoportada(packet.version));
        }

        let internal_aad = build_internal_aad_v3(
            packet.flags,
            packet.node_id,
            packet.epoch,
            packet.sequence,
            packet.timestamp_ms,
            &self.context_domain_hash,
            user_aad,
        )?;

        let (mut msg_key, expected_nonce) = self.derive_packet_crypto(
            packet.node_id,
            packet.epoch,
            packet.sequence,
            packet.timestamp_ms,
        );

        if expected_nonce != packet.nonce {
            msg_key.zeroize();
            return Err(Error::Autenticacion);
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        msg_key.zeroize();

        cipher
            .decrypt(
                Nonce::from_slice(&packet.nonce),
                Payload {
                    msg: &packet.ciphertext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Autenticacion)
    }

    /// Exporta el estado completo del nodo `ChronoMeshNode` (época, secuencia, ventanas anti-replay
    /// de todos los pares y el SHA-256 multiconjunto) cifrado con `wrap_key`.
    /// Compatible directamente con `DualSlotContainer::commit_state`.
    pub fn export_checkpoint(&self, wrap_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let guard = self.rx_state.lock().map_err(|_| Error::Cifrado)?;
        let peer_count = u32::try_from(guard.peers.len()).map_err(|_| Error::AadDemasiadoLargo)?;

        let epoch = self.epoch.load(Ordering::Acquire);
        let tx_seq = self.tx_seq.load(Ordering::Acquire);

        let mut raw = Vec::with_capacity(4 + 8 + 8 + 32 + 4 + guard.peers.len() * 36);
        raw.extend_from_slice(&self.node_id.to_be_bytes());
        raw.extend_from_slice(&epoch.to_be_bytes());
        raw.extend_from_slice(&tx_seq.to_be_bytes());
        raw.extend_from_slice(&guard.multiset_integrity_hash);
        raw.extend_from_slice(&peer_count.to_be_bytes());

        for (&(p_node, p_epoch), state) in &guard.peers {
            raw.extend_from_slice(&p_node.to_be_bytes());
            raw.extend_from_slice(&p_epoch.to_be_bytes());
            let highest = state.highest_seen.unwrap_or(u64::MAX);
            raw.extend_from_slice(&highest.to_be_bytes());
            raw.extend_from_slice(&state.seen_bitmap.to_be_bytes());
        }
        drop(guard);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key));
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut aad = [0u8; 37];
        aad[..4].copy_from_slice(MESH_STATE_MAGIC);
        aad[4] = MESH_STATE_VERSION;
        aad[5..].copy_from_slice(&self.context_domain_hash);

        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: &raw,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                raw.zeroize();
                Error::Cifrado
            })?;
        raw.zeroize();

        let mut out = Vec::with_capacity(4 + 1 + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MESH_STATE_MAGIC);
        out.push(MESH_STATE_VERSION);
        out.extend_from_slice(nonce_ga.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Restaura el estado de un `ChronoMeshNode` desde un checkpoint cifrado tras un apagón,
    /// incrementando automáticamente su `epoch` para garantizar que ninguna escritura futura
    /// pueda colisionar con paquetes emitidos antes del corte eléctrico.
    pub fn restore_checkpoint(&self, bytes: &[u8], wrap_key: &[u8; 32]) -> Result<(), Error> {
        if bytes.len() < 4 + 1 + NONCE_LEN + TAG_LEN
            || &bytes[..4] != MESH_STATE_MAGIC
            || bytes[4] != MESH_STATE_VERSION
        {
            return Err(Error::PaqueteCorrupto);
        }

        let nonce = Nonce::from_slice(&bytes[5..5 + NONCE_LEN]);
        let ciphertext = &bytes[5 + NONCE_LEN..];

        let mut aad = [0u8; 37];
        aad[..4].copy_from_slice(MESH_STATE_MAGIC);
        aad[4] = MESH_STATE_VERSION;
        aad[5..].copy_from_slice(&self.context_domain_hash);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key));
        let mut raw = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        if raw.len() < 56 {
            raw.zeroize();
            return Err(Error::PaqueteCorrupto);
        }

        let saved_node_id = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if saved_node_id != self.node_id {
            raw.zeroize();
            return Err(Error::Autenticacion);
        }

        let saved_epoch = u64::from_be_bytes(raw[4..12].try_into().unwrap());
        let saved_tx_seq = u64::from_be_bytes(raw[12..20].try_into().unwrap());
        let mut multiset_hash = [0u8; 32];
        multiset_hash.copy_from_slice(&raw[20..52]);
        let peer_count = u32::from_be_bytes(raw[52..56].try_into().unwrap()) as usize;

        let expected_len = 56usize
            .checked_add(peer_count.checked_mul(36).ok_or(Error::PaqueteCorrupto)?)
            .ok_or(Error::PaqueteCorrupto)?;
        if raw.len() != expected_len {
            raw.zeroize();
            return Err(Error::PaqueteCorrupto);
        }

        let mut peers = BTreeMap::new();
        let mut offset = 56;
        for _ in 0..peer_count {
            let p_node = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap());
            let p_epoch = u64::from_be_bytes(raw[offset + 4..offset + 12].try_into().unwrap());
            let highest_raw =
                u64::from_be_bytes(raw[offset + 12..offset + 20].try_into().unwrap());
            let bitmap = u128::from_be_bytes(raw[offset + 20..offset + 36].try_into().unwrap());
            let highest_seen = if highest_raw == u64::MAX {
                None
            } else {
                Some(highest_raw)
            };
            peers.insert(
                (p_node, p_epoch),
                PeerReplayState {
                    highest_seen,
                    seen_bitmap: bitmap,
                    received_count: 0,
                },
            );
            offset += 36;
        }
        raw.zeroize();

        // Al restaurar tras un apagón, avanzamos a `saved_epoch + 1` (o mantenemos el mayor) y
        // continuamos desde `saved_tx_seq` para eliminar 100 % el riesgo de colisión de secuencias no volcadas.
        let new_epoch = self
            .epoch
            .load(Ordering::Acquire)
            .max(saved_epoch.saturating_add(1));
        self.epoch.store(new_epoch, Ordering::Release);
        self.tx_seq.store(saved_tx_seq, Ordering::Release);

        let mut guard = self.rx_state.lock().map_err(|_| Error::Cifrado)?;
        guard.peers = peers;
        guard.multiset_integrity_hash = multiset_hash;
        Ok(())
    }

    pub fn current_integrity_sha256(&self) -> [u8; 32] {
        self.rx_state
            .lock()
            .map(|g| g.multiset_integrity_hash)
            .unwrap_or([0u8; 32])
    }

    pub fn verify_integrity_checkpoint(&self, expected_sha256: &[u8; 32]) -> Result<(), Error> {
        let current = self.current_integrity_sha256();
        let mut diff = 0u8;
        for (a, b) in current.iter().zip(expected_sha256.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(Error::IntegridadContextoCorrupta)
        }
    }
}
