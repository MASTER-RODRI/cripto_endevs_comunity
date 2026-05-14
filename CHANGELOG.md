# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0, breaking changes may land in minor releases (per pre-1.0 SemVer).

## [Unreleased]

### Changed

- **Wire format bumped to v2 for outbound packets.** Default `cifrar*` calls now
  emit `version=2` packets with an explicit `flags` byte. Wire v1 remains
  accepted inbound for the ordered channel for one release cycle.

### Added

- **Typed `Packet` API.** Callers can parse, inspect, serialize, and base64
  transport encrypted packets via `Packet::{from_bytes,to_bytes,from_base64,to_base64}`.
- **Configurable AAD.** `CryptoNugget::cifrar_bytes_with_aad` and
  `CryptoNugget::descifrar_bytes_with_aad` bind caller-supplied metadata into
  AES-GCM authentication without carrying that metadata in the wire packet.
- **Operation modes.** `Mode` and `Builder` make channel semantics explicit.
  PR3 ships `Mode::OrderedChannel` and `Mode::StatelessEnvelope`; replay-window
  mode remains reserved for PR4.
- **Stateless envelopes.** `StatelessEnvelope` encrypts independent blobs using
  per-message HKDF subkeys derived from the master seed and nonce.
- **Replay-window channel.** `ReplayWindowChannel` accepts out-of-order packets
  within a bounded sliding window and rejects repeats as `Error::Repetido` or
  stale packets as `Error::FueraDeOrden`.
- **Encrypted ordered-channel snapshots.** `CryptoNugget::export_state`,
  `CryptoNugget::import_state`, and `mark_resumed` persist ordered channel state
  under a caller-supplied 32-byte wrap key. Imported states cannot send until
  explicitly acknowledged and wrong wrap keys or contexts fail with
  `Error::Autenticacion`.
- **Migration guide.** See [`MIGRATION-0.3.md`](./MIGRATION-0.3.md) for the
  v1→v2 packet transition and AAD adoption rules.

### Internal

- **Module split (PR1 / Foundation).** `src/lib.rs` is now a thin facade that
  re-exports the public Spanish API (`MasterSeed`, `Role`, `CryptoNugget`,
  `Error`, `cifrar*` / `descifrar*`) from internal modules: `error`, `seed`,
  `modes::ordered` (current v0.2 channel), `modes::{envelope, replay}`,
  `packet`, `persistence`. The latter four are placeholder scaffolds for v0.3
  work and contain no behavior change. Public API and wire format are
  unchanged; all existing tests continue to pass.
- **Removed unused `rand` direct dependency.** Random nonces are sourced
  exclusively through `aes_gcm::aead::OsRng`; the top-level `rand` crate was
  never imported. This is a cleanup with no behavioral effect.

### Tooling

- **MSRV bumped to Rust 1.95.** Aligns `rust-version` in `Cargo.toml` with the
  toolchain used to develop and verify v0.3 work. Older toolchains will be
  rejected by `cargo` with a clear error rather than failing later on
  edition-2024 syntax.

## [0.2.0] - 2026-05-14

### Breaking changes

- **Removed `Error::Desincronizacion`.** Out-of-order, replayed, and tampered
  packets now surface uniformly as `Error::Autenticacion`, matching the actual
  AEAD failure mode. The previous variant was unreachable in practice because
  the sequence is bound into the AEAD AAD against the receiver's expected
  `rx_seq`. Callers that pattern-matched `Error::Desincronizacion` must
  collapse that arm into the `Error::Autenticacion` arm.
- **Removed `impl Clone for MasterSeed`.** Duplicating the root secret outside
  of the explicit `export_for_transfer` / `from_transfer_token` round-trip
  silently increased the surface area for key leakage. Callers that need a
  second instance must go through the transfer token path explicitly. This is
  secure-by-default: copying root key material now requires an intentional act.
- **`CryptoNugget::obtener_estado_adn` no longer leaks raw key bytes.** It now
  returns a non-reversible HKDF-SHA-256 fingerprint of the current TX/RX keys
  plus the current sequence numbers. The output format is stable within 0.x
  but is **not** part of the wire-format contract.

### Security

- Diagnostics (`obtener_estado_adn`) no longer expose prefixes of derived key
  material. Even partial key bytes in logs were a needless side channel; they
  are now replaced by a one-way fingerprint derived with HKDF-SHA-256 under a
  fixed domain label (`CryptoNugget:fingerprint:v1`).
- `MasterSeed` can no longer be implicitly duplicated; root-secret copies now
  require an explicit transfer-token round-trip.

### API additions

- Binary payload API: `CryptoNugget::cifrar_bytes` / `descifrar_bytes` for
  non-UTF-8 plaintexts (serialized structs, files, opaque blobs). Same wire
  format and same authentication guarantees as the UTF-8 variants.

### Tests, CI, documentation

- Adversarial integration suite under `tests/adversarial.rs` covers per-field
  tampering (version, sequence, nonce, tag), replay, future packets, role
  confusion, context isolation, binary and empty payloads, and `Debug`
  redaction.
- CI runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test` on
  Linux/macOS/Windows. `cargo audit` runs on every push, every PR, and on a
  weekly schedule to catch newly disclosed advisories between releases.
- README updated with the explicit MSRV (Rust 1.85+), the explicit `std`
  requirement (the crate is **not** `no_std`-compatible), the binary payload
  API, and the `0.2.0` install snippet.
- `Cargo.toml` now pins `rust-version = "1.85"` so `cargo` rejects builds on
  older toolchains rather than failing later with edition-2024 syntax errors.

## [0.1.2] - prior

- Initial published baseline: `MasterSeed`, `Role`, `CryptoNugget` with
  AES-256-GCM + HKDF-SHA-256 symmetric ratchet, base64 wire format, version
  byte, sequence-bound AAD, and `Zeroize`/`ZeroizeOnDrop` on key material.
