#![forbid(unsafe_code)]

//! # CryptoNugget
//!
//! Desarrollado por: ENRODMONTPAR (https://github.com/MASTER-RODRI)
//! Licencia: MIT
//!
//! Un micro-módulo de cifrado simétrico autenticado con ratcheting.
//!
//! Alcance deliberado: canales **ordenados** entre dos partes que ya comparten una
//! semilla maestra de alta entropía. No implementa intercambio de claves,
//! identidad, grupos, transporte ni forward secrecy completa si se filtra la
//! semilla raíz.
//!
//! ## Estructura interna (PR1 v0.3 hardening)
//!
//! La crate está dividida en módulos privados:
//! - [`error`] — enum [`Error`] tipado.
//! - [`seed`] — [`MasterSeed`] y helpers de transferencia.
//! - [`modes::ordered`] — modo histórico v0.2 ([`Role`], [`CryptoNugget`]).
//! - [`modes::envelope`], [`modes::replay`], [`packet`], [`persistence`] —
//!   esqueletos que se completan en PRs posteriores del plan v0.3.
//!
//! El API público se mantiene 100 % compatible con v0.2 vía `pub use`.

mod error;
mod modes;
mod packet;
mod persistence;
mod seed;

pub use crate::error::Error;
pub use crate::modes::envelope::StatelessEnvelope;
pub use crate::modes::ordered::{CryptoNugget, Role};
pub use crate::modes::replay::ReplayWindowChannel;
pub use crate::modes::{Builder, Mode};
pub use crate::packet::Packet;
pub use crate::seed::MasterSeed;
