//! Motor de Persistencia Resiliente a Apagones (`Crash-Proof Dual-Slot Superblock` + `ChronoVault WAL`).
//!
//! Diseñado como si nuestra supervivencia dependiera de no perder ni corromper un solo bit:
//!
//! 1. **Persistencia de Estado `CryptoNugget` y `ChronoMeshNode` (Snapshots Cifrados AEAD):**
//!    Exporta e importa el estado criptográfico completo (incluyendo acumuladores SHA-256 y ventanas anti-replay).
//!
//! 2. **Superbloque de Doble Ranura Auto-Recuperable (`DualSlotStorage` - Estilo Aeroespacial / SQLite WAL):**
//!    Si ocurre un apagón eléctrico *exactamente a mitad de la escritura* de un archivo de estado en disco,
//!    un archivo normal queda truncado e inservible. `DualSlotStorage` mantiene dos ranuras (`Slot A` y `Slot B`)
//!    con un contador de generación monotónico (`generation: u64`) y suma SHA-256 + AES-256-GCM.
//!    Si el corte de energía corrompe el `Slot B` mientras se guardaba, `recover_latest_valid()` detecta el
//!    fallo de autenticación en `Slot B` y recupera automáticamente el `Slot A` intacto sin intervención humana.
//!
//! 3. **Bitácora Cifrada Append-Only Encadenada por SHA-256 (`ChronoWalJournal`):**
//!    Para almacenar miles de fragmentos de contexto de IA o transacciones en tiempo real en disco o BD:
//!    Cada registro (`WalFrame`) sella criptográficamente el `prev_frame_sha256` (32 bytes), el `Packet` v3
//!    y calcula su propio `frame_sha256`.
//!    - Si un atacante intenta borrar un registro intermedio, reordenar dos registros o modificar 1 bit en disco,
//!      la cadena SHA-256 se rompe inmediatamente (`Error::IntegridadContextoCorrupta`).
//!    - Si ocurre un apagón a mitad de la escritura del último bloque en disco, `ChronoWalJournal::recover_from_bytes`
//!      verifica toda la cadena desde el génesis, rescata el 100 % de los paquetes completos y devuelve el offset
//!      exacto para truncar los bytes huérfanos del corte de luz (`WalRecoveryReport`).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{ChronoMeshNode, CryptoNugget, Error, Packet};

const MAGIC_CNST: &[u8; 4] = b"CNST";
const MAGIC_DUAL: &[u8; 4] = b"CNDS";
const MAGIC_WAL_FRAME: &[u8; 4] = b"CNWL";

const SNAPSHOT_VERSION_V1: u8 = 1;
const SNAPSHOT_VERSION_V2: u8 = 2;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_SNAPSHOT_LEN: usize = MAGIC_CNST.len() + 1 + NONCE_LEN + TAG_LEN;

// ============================================================================
// 1. PERSISTENCIA DE ESTADO DEL CANAL ORDENADO (`CryptoNugget`)
// ============================================================================

impl CryptoNugget {
    /// Exporta un snapshot cifrado y autenticado del estado del canal ordenado (Formato v2 con SHA-256).
    pub fn export_state(&mut self, wrap: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Cifrado)?;

        let mut state = encode_state_v2(self)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = snapshot_aad(SNAPSHOT_VERSION_V2, &self.context)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: &state,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                state.zeroize();
                Error::Cifrado
            })?;
        state.zeroize();

        let mut out = Vec::with_capacity(MIN_SNAPSHOT_LEN + ciphertext.len() - TAG_LEN);
        out.extend_from_slice(MAGIC_CNST);
        out.push(SNAPSHOT_VERSION_V2);
        out.extend_from_slice(nonce_ga.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Importa un snapshot cifrado (acepta v1 y v2) y lo deja bloqueado hasta `mark_resumed()`.
    pub fn import_state(bytes: &[u8], wrap: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        if bytes.len() < MIN_SNAPSHOT_LEN || &bytes[..4] != MAGIC_CNST {
            return Err(Error::PaqueteCorrupto);
        }
        let version = bytes[4];
        if version != SNAPSHOT_VERSION_V1 && version != SNAPSHOT_VERSION_V2 {
            return Err(Error::VersionNoSoportada(version));
        }

        let nonce = Nonce::from_slice(&bytes[5..5 + NONCE_LEN]);
        let ciphertext = &bytes[5 + NONCE_LEN..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
        let aad = snapshot_aad(version, context)?;
        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        let decoded = decode_state(version, &plaintext, context);
        plaintext.zeroize();
        decoded
    }

    /// Confirma explícitamente que el operador acepta reanudar desde snapshot.
    pub fn mark_resumed(&mut self) {
        self.requires_resume_ack = false;
    }
}

fn snapshot_aad(version: u8, context: &[u8]) -> Result<Vec<u8>, Error> {
    let ctx_len = u32::try_from(context.len()).map_err(|_| Error::AadDemasiadoLargo)?;
    let mut aad = Vec::with_capacity(4 + 1 + 4 + context.len());
    aad.extend_from_slice(MAGIC_CNST);
    aad.push(version);
    aad.extend_from_slice(&ctx_len.to_be_bytes());
    aad.extend_from_slice(context);
    Ok(aad)
}

fn encode_state_v2(nugget: &CryptoNugget) -> Result<Vec<u8>, Error> {
    let ctx_len = u32::try_from(nugget.context.len()).map_err(|_| Error::AadDemasiadoLargo)?;
    let mut state = Vec::with_capacity(32 + 32 + 8 + 8 + 8 + 32 + 32 + 4 + nugget.context.len());
    state.extend_from_slice(&nugget.tx_key);
    state.extend_from_slice(&nugget.rx_key);
    state.extend_from_slice(&nugget.tx_seq.to_be_bytes());
    state.extend_from_slice(&nugget.rx_seq.to_be_bytes());
    state.extend_from_slice(&nugget.epoch.to_be_bytes());
    state.extend_from_slice(&nugget.tx_transcript_hash);
    state.extend_from_slice(&nugget.rx_transcript_hash);
    state.extend_from_slice(&ctx_len.to_be_bytes());
    state.extend_from_slice(&nugget.context);
    Ok(state)
}

fn decode_state(version: u8, bytes: &[u8], expected_context: &[u8]) -> Result<CryptoNugget, Error> {
    let fixed_len = if version == SNAPSHOT_VERSION_V2 {
        32 + 32 + 8 + 8 + 8 + 32 + 32 + 4
    } else {
        32 + 32 + 8 + 8 + 8 + 4
    };

    if bytes.len() < fixed_len {
        return Err(Error::PaqueteCorrupto);
    }

    let mut tx_key = [0u8; 32];
    tx_key.copy_from_slice(&bytes[0..32]);
    let mut rx_key = [0u8; 32];
    rx_key.copy_from_slice(&bytes[32..64]);

    let tx_seq = u64::from_be_bytes(bytes[64..72].try_into().unwrap());
    let rx_seq = u64::from_be_bytes(bytes[72..80].try_into().unwrap());
    let epoch = u64::from_be_bytes(bytes[80..88].try_into().unwrap());

    let (tx_hash, rx_hash, len_offset) = if version == SNAPSHOT_VERSION_V2 {
        let mut th = [0u8; 32];
        let mut rh = [0u8; 32];
        th.copy_from_slice(&bytes[88..120]);
        rh.copy_from_slice(&bytes[120..152]);
        (th, rh, 152)
    } else {
        ([0u8; 32], [0u8; 32], 88)
    };

    let context_len =
        u32::from_be_bytes(bytes[len_offset..len_offset + 4].try_into().unwrap()) as usize;
    let context_end = match fixed_len.checked_add(context_len) {
        Some(end) if end == bytes.len() => end,
        _ => {
            tx_key.zeroize();
            rx_key.zeroize();
            return Err(Error::PaqueteCorrupto);
        }
    };

    let context = bytes[fixed_len..context_end].to_vec();
    if context.as_slice() != expected_context {
        tx_key.zeroize();
        rx_key.zeroize();
        return Err(Error::Autenticacion);
    }

    Ok(CryptoNugget::from_persisted_state(
        tx_key, rx_key, tx_seq, rx_seq, epoch, tx_hash, rx_hash, context,
    ))
}

// ============================================================================
// 2. SUPERBLOQUE DE DOBLE RANURA (`DualSlotContainer`) ANTI-APAGONES
// ============================================================================

/// Contenedor transaccional A/B en memoria/disco que garantiza supervivencia ante un apagón
/// ocurrido en el instante exacto en que se está escribiendo el estado en almacenamiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualSlotContainer {
    pub generation_a: u64,
    pub slot_a: Vec<u8>,
    pub generation_b: u64,
    pub slot_b: Vec<u8>,
}

impl Default for DualSlotContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl DualSlotContainer {
    pub fn new() -> Self {
        Self {
            generation_a: 0,
            slot_a: Vec::new(),
            generation_b: 0,
            slot_b: Vec::new(),
        }
    }

    /// Sella un payload de estado dentro de la ranura más antigua (sin tocar la última ranura válida).
    /// Así, si el servidor se apaga a mitad del volcado a disco, la otra ranura permanece 100 % íntegra.
    pub fn commit_state(&mut self, payload: &[u8], wrap_key: &[u8; 32]) -> Result<u64, Error> {
        let next_gen = self
            .generation_a
            .max(self.generation_b)
            .checked_add(1)
            .ok_or(Error::Cifrado)?;

        let sealed = Self::seal_slot(next_gen, payload, wrap_key)?;

        if self.generation_a <= self.generation_b {
            self.slot_a = sealed;
            self.generation_a = next_gen;
        } else {
            self.slot_b = sealed;
            self.generation_b = next_gen;
        }
        Ok(next_gen)
    }

    /// Intenta recuperar la generación más reciente. Si la ranura más reciente se corrompió por un
    /// apagón a mitad de escritura, hace fallback automático e inmediato a la ranura anterior.
    pub fn recover_latest_valid(&self, wrap_key: &[u8; 32]) -> Result<(u64, Vec<u8>), Error> {
        let primary_first = if self.generation_a >= self.generation_b {
            [
                (&self.slot_a, self.generation_a),
                (&self.slot_b, self.generation_b),
            ]
        } else {
            [
                (&self.slot_b, self.generation_b),
                (&self.slot_a, self.generation_a),
            ]
        };

        for (slot_bytes, expected_gen) in primary_first {
            if !slot_bytes.is_empty()
                && expected_gen > 0
                && let Ok((gen_val, data)) = Self::open_slot(slot_bytes, wrap_key)
                && gen_val == expected_gen
            {
                return Ok((gen_val, data));
            }
        }
        Err(Error::PaqueteCorrupto)
    }

    /// Serializa ambas ranuras A y B en un único buffer listo para guardarse en disco o BD.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let len_a = u32::try_from(self.slot_a.len()).map_err(|_| Error::AadDemasiadoLargo)?;
        let len_b = u32::try_from(self.slot_b.len()).map_err(|_| Error::AadDemasiadoLargo)?;

        let mut out = Vec::with_capacity(4 + 8 + 4 + self.slot_a.len() + 8 + 4 + self.slot_b.len());
        out.extend_from_slice(MAGIC_DUAL);
        out.extend_from_slice(&self.generation_a.to_be_bytes());
        out.extend_from_slice(&len_a.to_be_bytes());
        out.extend_from_slice(&self.slot_a);
        out.extend_from_slice(&self.generation_b.to_be_bytes());
        out.extend_from_slice(&len_b.to_be_bytes());
        out.extend_from_slice(&self.slot_b);
        Ok(out)
    }

    /// Reconstruye el contenedor Dual-Slot incluso si el final del archivo sufrió truncamiento parcial.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 + 8 + 4 || &bytes[..4] != MAGIC_DUAL {
            return Err(Error::PaqueteCorrupto);
        }
        let generation_a = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let len_a = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let end_a = 16usize.checked_add(len_a).ok_or(Error::PaqueteCorrupto)?;
        if bytes.len() < end_a {
            return Err(Error::PaqueteCorrupto);
        }
        let slot_a = bytes[16..end_a].to_vec();

        // Si el archivo se truncó escribiendo el Slot B, aún rescatamos el Slot A completo
        if bytes.len() < end_a + 12 {
            return Ok(Self {
                generation_a,
                slot_a,
                generation_b: 0,
                slot_b: Vec::new(),
            });
        }
        let generation_b = u64::from_be_bytes(bytes[end_a..end_a + 8].try_into().unwrap());
        let len_b = u32::from_be_bytes(bytes[end_a + 8..end_a + 12].try_into().unwrap()) as usize;
        let end_b = (end_a + 12)
            .checked_add(len_b)
            .ok_or(Error::PaqueteCorrupto)?;

        let slot_b = if bytes.len() >= end_b {
            bytes[end_a + 12..end_b].to_vec()
        } else {
            // Slot B quedó a medio escribir por apagón; se ignora limpiamente para usar Slot A
            Vec::new()
        };

        Ok(Self {
            generation_a,
            slot_a,
            generation_b,
            slot_b,
        })
    }

    fn seal_slot(generation: u64, payload: &[u8], wrap_key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key));
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut aad = [0u8; 12];
        aad[..4].copy_from_slice(MAGIC_DUAL);
        aad[4..].copy_from_slice(&generation.to_be_bytes());

        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: payload,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;

        let mut out = Vec::with_capacity(8 + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(nonce_ga.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_slot(slot_bytes: &[u8], wrap_key: &[u8; 32]) -> Result<(u64, Vec<u8>), Error> {
        if slot_bytes.len() < 8 + NONCE_LEN + TAG_LEN {
            return Err(Error::PaqueteCorrupto);
        }
        let generation = u64::from_be_bytes(slot_bytes[..8].try_into().unwrap());
        let nonce = Nonce::from_slice(&slot_bytes[8..8 + NONCE_LEN]);
        let ciphertext = &slot_bytes[8 + NONCE_LEN..];

        let mut aad = [0u8; 12];
        aad[..4].copy_from_slice(MAGIC_DUAL);
        aad[4..].copy_from_slice(&generation.to_be_bytes());

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap_key));
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        Ok((generation, plaintext))
    }

    /// Guarda el contenedor en disco de forma 100 % atómica y a prueba de apagones.
    ///
    /// Protocolo:
    /// 1. Escribe en un archivo temporal en el mismo directorio (`<path>.tmp.<pid>`).
    /// 2. Ejecuta `sync_all()` (`fdatasync` / `FlushFileBuffers`) para vaciar el caché del SO y SSD.
    /// 3. Ejecuta `fs::rename` atómico que reemplaza el archivo de destino sin ventanas de corrupción.
    /// 4. Sincroniza el directorio padre para asegurar la durabilidad de la entrada de inodo/MFT.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let bytes = self.to_bytes()?;

        let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| Error::Io(e.to_string()))?;

        file.write_all(&bytes)
            .map_err(|e| Error::Io(e.to_string()))?;
        file.sync_all().map_err(|e| Error::Io(e.to_string()))?;
        drop(file);

        fs::rename(&tmp_path, path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            Error::Io(e.to_string())
        })?;

        if let Some(parent) = path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Carga el contenedor desde un archivo en disco.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

// ============================================================================
// 3. BITÁCORA WAL ENCADENADA POR SHA-256 (`ChronoWalJournal`) PARA CONTEXTO IA
// ============================================================================

/// Reporte devuelto al recuperar una bitácora WAL tras un apagón o reinicio del servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecoveryReport {
    /// Paquetes íntegros verificados por cadena SHA-256 de principio a fin.
    pub packets: Vec<Packet>,
    /// Último hash SHA-256 de la cadena (sirve para continuar haciendo append tras el reinicio).
    pub head_chain_sha256: [u8; 32],
    /// Cantidad de bytes válidos confirmados (si el archivo en disco tenía bytes extra por un
    /// corte de luz a mitad del último registro, puedes truncar el archivo exactamente en `valid_bytes_len`).
    pub valid_bytes_len: usize,
    /// Indica si se detectó y descartó una cola incompleta al final del archivo producto de un apagón.
    pub had_truncated_tail: bool,
}

/// Bitácora de persistencia inmutable encadenada por SHA-256 (Write-Ahead Log Criptográfico).
///
/// Cada frame tiene la estructura:
/// `MAGIC("CNWL": 4B) || packet_len(4B BE) || prev_sha256(32B) || packet_bytes(N) || frame_sha256(32B)`
#[derive(Debug, Clone)]
pub struct ChronoWalJournal {
    head_sha256: [u8; 32],
    frames_count: u64,
}

impl Default for ChronoWalJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl ChronoWalJournal {
    pub fn new() -> Self {
        Self {
            head_sha256: [0u8; 32],
            frames_count: 0,
        }
    }

    /// Reanuda un `ChronoWalJournal` desde un hash de cabeza previamente recuperado.
    pub fn from_head(head_sha256: [u8; 32], frames_count: u64) -> Self {
        Self {
            head_sha256,
            frames_count,
        }
    }

    pub fn head_sha256(&self) -> [u8; 32] {
        self.head_sha256
    }

    pub fn frames_count(&self) -> u64 {
        self.frames_count
    }

    /// Empaqueta un `Packet` en un frame WAL encadenado con el `SHA-256` del registro anterior.
    /// El resultado puede escribirse con `append` directamente a un archivo o tabla de base de datos.
    pub fn encode_append_frame(&mut self, packet: &Packet) -> Result<Vec<u8>, Error> {
        let pkt_bytes = packet.to_bytes();
        let pkt_len = u32::try_from(pkt_bytes.len()).map_err(|_| Error::AadDemasiadoLargo)?;

        let frame_sha = Self::compute_frame_sha256(&self.head_sha256, &pkt_bytes);

        let mut frame = Vec::with_capacity(4 + 4 + 32 + pkt_bytes.len() + 32);
        frame.extend_from_slice(MAGIC_WAL_FRAME);
        frame.extend_from_slice(&pkt_len.to_be_bytes());
        frame.extend_from_slice(&self.head_sha256);
        frame.extend_from_slice(&pkt_bytes);
        frame.extend_from_slice(&frame_sha);

        self.head_sha256 = frame_sha;
        self.frames_count = self.frames_count.saturating_add(1);
        Ok(frame)
    }

    /// Añade un frame al final de un archivo WAL en disco de forma duradera y resiliente a apagones.
    /// Ejecuta `sync_data()` / `sync_all()` para garantizar que los datos crucen el caché del SO y del SSD.
    pub fn append_to_file(&mut self, path: impl AsRef<Path>, packet: &Packet) -> Result<(), Error> {
        let frame = self.encode_append_frame(packet)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| Error::Io(e.to_string()))?;

        file.write_all(&frame)
            .map_err(|e| Error::Io(e.to_string()))?;
        file.sync_data().map_err(|e| Error::Io(e.to_string()))?;
        Ok(())
    }

    /// Recupera y auto-repara un archivo WAL en disco tras un apagón o reinicio.
    /// Si el archivo termina con un frame incompleto (corte de luz a mitad de append),
    /// trunca el archivo en el byte exacto (`valid_bytes_len`) y lo sincroniza a disco.
    pub fn recover_from_file(path: impl AsRef<Path>) -> Result<(Self, WalRecoveryReport), Error> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok((
                Self::new(),
                WalRecoveryReport {
                    packets: Vec::new(),
                    head_chain_sha256: [0u8; 32],
                    valid_bytes_len: 0,
                    had_truncated_tail: false,
                },
            ));
        }

        let bytes = fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
        let report = Self::recover_from_bytes(&bytes)?;

        if report.had_truncated_tail {
            let file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| Error::Io(e.to_string()))?;
            file.set_len(report.valid_bytes_len as u64)
                .map_err(|e| Error::Io(e.to_string()))?;
            file.sync_all().map_err(|e| Error::Io(e.to_string()))?;
        }

        let journal = Self::from_head(report.head_chain_sha256, report.packets.len() as u64);
        Ok((journal, report))
    }

    /// Escanea un flujo de bytes de bitácora WAL (ej. leído del disco tras un apagón):
    /// - Verifica que cada registro esté encadenado con `prev_sha256` sin huecos ni alteraciones.
    /// - Si un atacante alteró un byte en medio del archivo, devuelve `Err(Error::IntegridadContextoCorrupta)`.
    /// - Si el último frame al final del archivo quedó incompleto porque se cortó la energía mientras se
    ///   escribía en el disco, rescata todos los frames anteriores intactos y marca `had_truncated_tail = true`.
    pub fn recover_from_bytes(wal_bytes: &[u8]) -> Result<WalRecoveryReport, Error> {
        let mut offset = 0usize;
        let mut expected_prev_sha = [0u8; 32];
        let mut packets = Vec::new();
        let mut had_truncated_tail = false;

        while offset < wal_bytes.len() {
            let remaining = wal_bytes.len() - offset;
            // Cabecera mínima de un frame = 4 (magic) + 4 (len) + 32 (prev_sha) + 32 (frame_sha) = 72 bytes
            if remaining < 72 {
                had_truncated_tail = true;
                break;
            }

            if &wal_bytes[offset..offset + 4] != MAGIC_WAL_FRAME {
                return Err(Error::PaqueteCorrupto);
            }

            let pkt_len =
                u32::from_be_bytes(wal_bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let total_frame_len = match 72usize.checked_add(pkt_len) {
                Some(len) => len,
                None => return Err(Error::PaqueteCorrupto),
            };

            // Si el archivo termina antes de completar el último frame, fue un apagón a mitad del append
            if remaining < total_frame_len {
                had_truncated_tail = true;
                break;
            }

            let prev_sha = &wal_bytes[offset + 8..offset + 40];
            let pkt_slice = &wal_bytes[offset + 40..offset + 40 + pkt_len];
            let stored_frame_sha = &wal_bytes[offset + 40 + pkt_len..offset + total_frame_len];

            // Comparación en tiempo constante del encadenamiento previo
            if !constant_time_eq_32(prev_sha, &expected_prev_sha) {
                return Err(Error::IntegridadContextoCorrupta);
            }

            let computed_sha = Self::compute_frame_sha256(&expected_prev_sha, pkt_slice);
            if !constant_time_eq_32(stored_frame_sha, &computed_sha) {
                return Err(Error::IntegridadContextoCorrupta);
            }

            let packet = Packet::from_bytes(pkt_slice)?;
            packets.push(packet);
            expected_prev_sha = computed_sha;
            offset += total_frame_len;
        }

        Ok(WalRecoveryReport {
            packets,
            head_chain_sha256: expected_prev_sha,
            valid_bytes_len: offset,
            had_truncated_tail,
        })
    }

    /// Descifra y verifica en bloque todos los paquetes de una bitácora WAL usando un `ChronoMeshNode`.
    pub fn decrypt_recovered_wal(
        node: &ChronoMeshNode,
        report: &WalRecoveryReport,
        user_aad: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut plaintexts = Vec::with_capacity(report.packets.len());
        for pkt in &report.packets {
            let pt = node.open_persisted_record(pkt, user_aad)?;
            plaintexts.push(pt);
        }
        Ok(plaintexts)
    }

    fn compute_frame_sha256(prev_sha: &[u8; 32], pkt_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"CryptoNugget:WAL:Frame:v1");
        hasher.update(prev_sha);
        hasher.update((pkt_bytes.len() as u64).to_be_bytes());
        hasher.update(pkt_bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[inline]
fn constant_time_eq_32(a: &[u8], b: &[u8; 32]) -> bool {
    if a.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
