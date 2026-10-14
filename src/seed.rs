//! Semilla maestra (`MasterSeed`) y derivación determinista jerárquica.
//!
//! Permite derivar sub-semillas aisladas para almacenamiento persistente (`WAL`),
//! nodos de borde (Web/Mobile) y servicios backend sin exponer la clave raíz.

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

/// Semilla maestra de 256 bits con limpieza automática en RAM al destruirse.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed {
    bytes: [u8; 32],
}

impl std::fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterSeed")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl MasterSeed {
    /// Genera una semilla maestra usando el CSPRNG del sistema operativo.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construye una semilla desde exactamente 32 bytes verificando que no sea nula
    /// ni trivialmente constante (mitiga fallos de inicialización en FFI).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let first = bytes[0];
        if bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == first) {
            return Err(Error::SemillaInvalida);
        }
        Ok(Self { bytes })
    }

    /// Importa una semilla previamente exportada en Base64 limpiando el buffer intermedio.
    pub fn from_transfer_token(token: &str) -> Result<Self, Error> {
        let mut decoded = STANDARD
            .decode(token)
            .map_err(|e| Error::Base64(e.to_string()))?;
        let res = match decoded.as_slice().try_into() {
            Ok(arr) => Self::from_bytes(arr),
            Err(_) => Err(Error::SemillaInvalida),
        };
        decoded.zeroize();
        res
    }

    /// Exporta la semilla en Base64 para aprovisionamiento seguro entre nodos.
    pub fn export_for_transfer(&self) -> String {
        STANDARD.encode(self.bytes)
    }

    /// Deriva una sub-semilla determinista aislada por propósito o rol (`purpose`).
    /// Ejemplo: `seed.derive_subseed(b"storage:wal:wrap-key")` para cifrar el estado en disco.
    pub fn derive_subseed(&self, purpose: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:subseed:v1"), &self.bytes);
        let mut sub = [0u8; 32];
        hkdf.expand(purpose, &mut sub)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        Self { bytes: sub }
    }

    /// Deriva una clave cruda de 32 bytes para envolver snapshots (`wrap_key`) de forma determinista.
    pub fn derive_wrap_key(&self, storage_domain: &[u8]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:wrap-key:v1"), &self.bytes);
        let mut wrap = [0u8; 32];
        hkdf.expand(storage_domain, &mut wrap)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        wrap
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
