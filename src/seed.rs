//! Semilla maestra (`MasterSeed`) y helpers de transferencia.
//!
//! Aislado en su propio módulo para que los modos (`ordered`, `envelope`,
//! `replay`) y el handshake opcional puedan compartir el mismo tipo raíz sin
//! depender directamente de `lib.rs`.

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

/// Semilla maestra de 256 bits.
///
/// La forma normal de crearla es [`MasterSeed::generate`]. Para compartirla entre
/// dispositivos existe [`MasterSeed::export_for_transfer`], pero eso debe tratarse
/// como material secreto: no logs, no URLs públicas, no analytics, no capturas.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed {
    bytes: [u8; 32],
}

impl std::fmt::Debug for MasterSeed {
    /// Implementación segura: nunca expone los bytes de la semilla.
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

    /// Construye una semilla desde exactamente 32 bytes.
    ///
    /// Usalo solo si esos bytes ya vienen de una fuente de alta entropía.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::SemillaInvalida);
        }

        Ok(Self { bytes })
    }

    /// Importa una semilla previamente exportada para transferencia segura.
    pub fn from_transfer_token(token: &str) -> Result<Self, Error> {
        let decoded = STANDARD
            .decode(token)
            .map_err(|e| Error::Base64(e.to_string()))?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| Error::SemillaInvalida)?;
        Self::from_bytes(bytes)
    }

    /// Exporta la semilla para transferirla a otro dispositivo/proyecto.
    ///
    /// Este valor es equivalente a la clave raíz. Exponerlo compromete toda la
    /// sesión derivada de esta semilla.
    pub fn export_for_transfer(&self) -> String {
        STANDARD.encode(self.bytes)
    }

    /// Acceso interno (a nivel de crate) a los bytes crudos.
    ///
    /// No es público: solo los módulos internos que necesitan derivar claves
    /// (HKDF en cada modo) deberían tocar este material directamente.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// `MasterSeed` no implementa `Clone` deliberadamente: duplicar el material raíz
// fuera de `export_for_transfer` aumenta la superficie de fuga de claves. Si
// necesitás una segunda copia para transferir, usá `export_for_transfer` y
// reconstruí con `from_transfer_token`.
