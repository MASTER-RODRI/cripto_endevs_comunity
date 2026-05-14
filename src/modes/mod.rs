//! Modos de operación del canal.
//!
//! `ordered` conserva el canal ratcheado histórico. `envelope` implementa un
//! sobre stateless para mensajes independientes. `replay` se completa en PR4.

use crate::{CryptoNugget, Error, MasterSeed, ReplayWindowChannel, Role, StatelessEnvelope};

pub mod envelope;
pub mod ordered;
pub mod replay;

/// Modo de operación explícito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Canal ratcheado y estrictamente ordenado. Es el comportamiento por defecto.
    OrderedChannel,
    /// Sobre stateless: cada mensaje deriva su propia clave desde la semilla y nonce.
    StatelessEnvelope,
    /// Modo de ventana de replay. Se implementa en PR4.
    ReplayWindowChannel { window: u64 },
}

/// Builder para construir el modo elegido sin perder la API simple existente.
#[derive(Debug, Clone)]
pub struct Builder<'a> {
    seed: &'a MasterSeed,
    role: Role,
    context: &'a [u8],
    mode: Mode,
}

impl<'a> Builder<'a> {
    pub(crate) fn new(seed: &'a MasterSeed, role: Role, context: &'a [u8]) -> Self {
        Self {
            seed,
            role,
            context,
            mode: Mode::OrderedChannel,
        }
    }

    /// Selecciona el modo de operación.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Construye un canal ordenado.
    pub fn build_ordered(self) -> Result<CryptoNugget, Error> {
        match self.mode {
            Mode::OrderedChannel => Ok(CryptoNugget::new_with_context(
                self.seed,
                self.role,
                self.context,
            )),
            Mode::StatelessEnvelope | Mode::ReplayWindowChannel { .. } => Err(Error::ModoInvalido),
        }
    }

    /// Construye un sobre stateless.
    pub fn build_stateless_envelope(self) -> Result<StatelessEnvelope, Error> {
        match self.mode {
            Mode::StatelessEnvelope => {
                Ok(StatelessEnvelope::new_with_context(self.seed, self.context))
            }
            Mode::OrderedChannel | Mode::ReplayWindowChannel { .. } => Err(Error::ModoInvalido),
        }
    }

    /// Construye un canal con ventana anti-replay.
    ///
    /// Este modo NO usa ratchet por mensaje; ver `SECURITY.md` antes de usarlo.
    pub fn build_replay_window(self) -> Result<ReplayWindowChannel, Error> {
        match self.mode {
            Mode::ReplayWindowChannel { window } => {
                ReplayWindowChannel::new_with_context(self.seed, self.role, self.context, window)
            }
            Mode::OrderedChannel | Mode::StatelessEnvelope => Err(Error::ModoInvalido),
        }
    }
}
