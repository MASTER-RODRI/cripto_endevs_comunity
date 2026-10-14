#![deny(unsafe_code)]

//! # CryptoNugget (v0.5 - Multi-Language FFI & Self-Healing Persistence Edition)
//!
//! Desarrollado por: ENRODMONTPAR (https://github.com/MASTER-RODRI)
//! Licencia: MIT
//!
//! Arquitectura criptográfica basada en el tiempo, distribuida, multi-lenguaje y resistente a apagones:
//! - **Núcleo Rust 100 % Memory-Safe (`#![deny(unsafe_code)]`)** con limpieza determinista `Zeroize`.
//! - **Persistencia Inmune a Apagones (`DualSlotContainer` + `ChronoWalJournal`):** Superbloque A/B
//!   auto-reparable y bitácora append-only encadenada con SHA-256 que detecta truncamientos por corte
//!   eléctrico y recupera el 100 % de los registros previos sin corromper la memoria de la IA.
//! - **Interoperabilidad Universal (`ffi.rs`):** C-ABI lista para C# (.NET P/Invoke), C/C++, Java,
//!   TypeScript/Node y WebAssembly.

mod error;
pub mod ffi;
mod modes;
mod packet;
mod persistence;
mod seed;

pub use crate::error::Error;
pub use crate::modes::chrono::ChronoMeshNode;
pub use crate::modes::envelope::StatelessEnvelope;
pub use crate::modes::ordered::{CryptoNugget, Role};
pub use crate::modes::replay::ReplayWindowChannel;
pub use crate::modes::{Builder, Mode};
pub use crate::packet::{
    FLAG_AAD_PRESENT, FLAG_INTEGRITY_HASH_BOUND, Packet, V1_HEADER_LEN, V2_HEADER_LEN,
    V3_HEADER_LEN, WIRE_VERSION_V1, WIRE_VERSION_V2, WIRE_VERSION_V3,
};
pub use crate::persistence::{ChronoWalJournal, DualSlotContainer, WalRecoveryReport};
pub use crate::seed::MasterSeed;
