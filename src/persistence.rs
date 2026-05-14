//! Persistencia de estado cifrada para `CryptoNugget`.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use zeroize::Zeroize;

use crate::{CryptoNugget, Error};

const MAGIC: &[u8; 4] = b"CNST";
const SNAPSHOT_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_SNAPSHOT_LEN: usize = MAGIC.len() + 1 + NONCE_LEN + TAG_LEN;

impl CryptoNugget {
    /// Exporta un snapshot cifrado y autenticado del estado del canal ordenado.
    ///
    /// El `wrap` debe ser una clave aleatoria de 32 bytes. La crate no deriva
    /// esta clave desde passphrases; hacelo fuera con un KDF apropiado.
    pub fn export_state(&mut self, wrap: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Cifrado)?;

        let mut state = encode_state(self);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = snapshot_aad(&self.context);
        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: &state,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;
        state.zeroize();

        let mut out = Vec::with_capacity(MIN_SNAPSHOT_LEN + ciphertext.len() - TAG_LEN);
        out.extend_from_slice(MAGIC);
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(nonce_ga.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Importa un snapshot cifrado y lo deja bloqueado hasta `mark_resumed()`.
    pub fn import_state(bytes: &[u8], wrap: &[u8; 32], context: &[u8]) -> Result<Self, Error> {
        if bytes.len() < MIN_SNAPSHOT_LEN || &bytes[..4] != MAGIC || bytes[4] != SNAPSHOT_VERSION {
            return Err(Error::PaqueteCorrupto);
        }

        let nonce = Nonce::from_slice(&bytes[5..5 + NONCE_LEN]);
        let ciphertext = &bytes[5 + NONCE_LEN..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wrap));
        let aad = snapshot_aad(context);
        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Autenticacion)?;

        let decoded = decode_state(&plaintext, context);
        plaintext.zeroize();
        decoded
    }

    /// Confirma explícitamente que el operador acepta reanudar desde snapshot.
    pub fn mark_resumed(&mut self) {
        self.requires_resume_ack = false;
    }
}

fn snapshot_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 1 + 4 + context.len());
    aad.extend_from_slice(MAGIC);
    aad.push(SNAPSHOT_VERSION);
    aad.extend_from_slice(&(context.len() as u32).to_be_bytes());
    aad.extend_from_slice(context);
    aad
}

fn encode_state(nugget: &CryptoNugget) -> Vec<u8> {
    let mut state = Vec::with_capacity(32 + 32 + 8 + 8 + 8 + 4 + nugget.context.len());
    state.extend_from_slice(&nugget.tx_key);
    state.extend_from_slice(&nugget.rx_key);
    state.extend_from_slice(&nugget.tx_seq.to_be_bytes());
    state.extend_from_slice(&nugget.rx_seq.to_be_bytes());
    state.extend_from_slice(&nugget.epoch.to_be_bytes());
    state.extend_from_slice(&(nugget.context.len() as u32).to_be_bytes());
    state.extend_from_slice(&nugget.context);
    state
}

fn decode_state(bytes: &[u8], expected_context: &[u8]) -> Result<CryptoNugget, Error> {
    const FIXED_LEN: usize = 32 + 32 + 8 + 8 + 8 + 4;
    if bytes.len() < FIXED_LEN {
        return Err(Error::PaqueteCorrupto);
    }

    let mut tx_key = [0u8; 32];
    tx_key.copy_from_slice(&bytes[0..32]);
    let mut rx_key = [0u8; 32];
    rx_key.copy_from_slice(&bytes[32..64]);
    let tx_seq = u64::from_be_bytes(
        bytes[64..72]
            .try_into()
            .map_err(|_| Error::PaqueteCorrupto)?,
    );
    let rx_seq = u64::from_be_bytes(
        bytes[72..80]
            .try_into()
            .map_err(|_| Error::PaqueteCorrupto)?,
    );
    let epoch = u64::from_be_bytes(
        bytes[80..88]
            .try_into()
            .map_err(|_| Error::PaqueteCorrupto)?,
    );
    let context_len = u32::from_be_bytes(
        bytes[88..92]
            .try_into()
            .map_err(|_| Error::PaqueteCorrupto)?,
    ) as usize;
    let context_end = FIXED_LEN
        .checked_add(context_len)
        .ok_or(Error::PaqueteCorrupto)?;
    if bytes.len() != context_end {
        return Err(Error::PaqueteCorrupto);
    }
    let context = bytes[FIXED_LEN..context_end].to_vec();
    if context != expected_context {
        return Err(Error::Autenticacion);
    }

    Ok(CryptoNugget::from_persisted_state(
        tx_key, rx_key, tx_seq, rx_seq, epoch, context,
    ))
}
