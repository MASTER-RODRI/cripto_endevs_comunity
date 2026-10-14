//! Modos de operación del canal.
//!
//! - `ordered`: Canal ratcheado secuencial punto a punto con SHA-256 Transcript Accumulator.
//! - `envelope`: Sobre stateless para blobs independientes.
//! - `replay`: Canal con ventana anti-replay y nonces deterministas enmascarados.
//! - `chrono`: Nuevo motor `ChronoMeshNode` v3 para arquitecturas distribuidas, concurrencia
//!   multi-instancia, cifrado vinculado al tiempo y recuperación automática ante apagones.

use crate::{
    ChronoMeshNode, CryptoNugget, Error, MasterSeed, ReplayWindowChannel, Role, StatelessEnvelope,
};

pub mod chrono;
pub mod envelope;
pub mod ordered;
pub mod replay;

/// Modo de operación explícito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Canal ratcheado y estrictamente ordenado.
    OrderedChannel,
    /// Sobre stateless: cada mensaje deriva su propia clave desde la semilla y nonce.
    StatelessEnvelope,
    /// Modo de ventana de replay con clave fija y nonce determinista.
    ReplayWindowChannel { window: u64 },
    /// Malla distribuida basada en tiempo, concurrente y resistente a apagones.
    ChronoMesh {
        node_id: u32,
        boot_epoch: u64,
        max_time_drift_ms: u64,
    },
}

/// Builder para construir el modo elegido manteniendo compatibilidad con v0.2/v0.3.
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

    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn build_ordered(self) -> Result<CryptoNugget, Error> {
        match self.mode {
            Mode::OrderedChannel => Ok(CryptoNugget::new_with_context(
                self.seed,
                self.role,
                self.context,
            )),
            _ => Err(Error::ModoInvalido),
        }
    }

    pub fn build_stateless_envelope(self) -> Result<StatelessEnvelope, Error> {
        match self.mode {
            Mode::StatelessEnvelope => {
                Ok(StatelessEnvelope::new_with_context(self.seed, self.context))
            }
            _ => Err(Error::ModoInvalido),
        }
    }

    pub fn build_replay_window(self) -> Result<ReplayWindowChannel, Error> {
        match self.mode {
            Mode::ReplayWindowChannel { window } => {
                ReplayWindowChannel::new_with_context(self.seed, self.role, self.context, window)
            }
            _ => Err(Error::ModoInvalido),
        }
    }

    pub fn build_chrono_mesh(self) -> Result<ChronoMeshNode, Error> {
        match self.mode {
            Mode::ChronoMesh {
                node_id,
                boot_epoch,
                max_time_drift_ms,
            } => Ok(ChronoMeshNode::new(
                self.seed,
                self.context,
                node_id,
                boot_epoch,
                max_time_drift_ms,
            )),
            _ => Err(Error::ModoInvalido),
        }
    }
}
