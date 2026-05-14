# CryptoNugget

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Crates.io](https://img.shields.io/crates/v/cripto_endevs_comunity)](https://crates.io/crates/cripto_endevs_comunity)
[![CI](https://github.com/MASTER-RODRI/cripto_endevs_comunity/actions/workflows/ci.yml/badge.svg)](https://github.com/MASTER-RODRI/cripto_endevs_comunity/actions/workflows/ci.yml)

> A small, misuse-resistant **two-party authenticated channel** in Rust. AES-256-GCM, HKDF-SHA-256, symmetric ratchet, zeroized state, no `unsafe`.

**Use it when** you have two participants, a way to share a 32-byte secret over a separate secure channel, and you need an authenticated, ordered, replay-resistant message stream.

**Don't use it when** you need key exchange, group messaging, identity, multi-device sync, or out-of-order delivery. See [Limitations](#limitations--non-goals).

---

## Table of contents

- [Quickstart](#quickstart)
- [Install](#install)
- [API at a glance](#api-at-a-glance)
- [Security model](#security-model)
- [Threat model](#threat-model)
- [Limitations & non-goals](#limitations--non-goals)
- [Performance & reliability](#performance--reliability)
- [Testing & CI](#testing--ci)
- [Safe-usage checklist](#safe-usage-checklist)
- [Versioning & wire format](#versioning--wire-format)
- [License](#license)

---

## Quickstart

```rust
use cripto_endevs_comunity::{CryptoNugget, MasterSeed, Role};

// 1. One side generates the seed.
let seed = MasterSeed::generate();

// 2. Transfer the seed to the other side over a SECURE, EPHEMERAL channel.
//    The token below is equivalent to the root key — never log it.
let token = seed.export_for_transfer();
let seed_peer = MasterSeed::from_transfer_token(&token).unwrap();

// 3. Each side instantiates with its explicit role.
let mut alice = CryptoNugget::new(&seed,      Role::Initiator);
let mut bob   = CryptoNugget::new(&seed_peer, Role::Responder);

// 4. Send.
let pkt = alice.cifrar("hello bob").unwrap();

// 5. Receive — keys auto-ratchet on success.
assert_eq!(bob.descifrar(&pkt).unwrap(), "hello bob");
```

Run the bundled demo:

```bash
cargo run --example demo
```

---

## Install

```toml
[dependencies]
cripto_endevs_comunity = "0.2.0"
```

Requirements:

- Rust **1.85+** stable (edition 2024 requires 1.85 or newer).
- Standard library (`std`). This crate is **not** `no_std`-compatible.
- No optional features; the default build is the supported configuration.

---

## API at a glance

### Types

| Type           | Purpose                                             |
|----------------|-----------------------------------------------------|
| `MasterSeed`   | 256-bit root secret. `Zeroize`d on drop. Safe `Debug` (redacted). |
| `Role`         | `Initiator` or `Responder`. Replaces fragile booleans. |
| `CryptoNugget` | Per-peer state. `Zeroize`d on drop. Safe `Debug`.   |
| `Packet`       | Typed encrypted packet: parse/serialize bytes or base64 and inspect version/flags/sequence. |
| `Mode` / `Builder` | Explicitly select ordered or stateless-envelope semantics. |
| `StatelessEnvelope` | Encrypt independent blobs without channel state or replay tracking. |
| `ReplayWindowChannel` | Accept out-of-order packets within a bounded anti-replay window. |
| `Error`        | Typed errors: tampering, replay, version, format.   |

### Methods you'll actually use

| Call                                                      | What it does                                          |
|-----------------------------------------------------------|-------------------------------------------------------|
| `MasterSeed::generate()`                                  | New seed from `OsRng`.                                |
| `MasterSeed::from_transfer_token(&str)`                   | Import a seed shared via secure channel.              |
| `seed.export_for_transfer()`                              | Export the seed as a base64 token (handle as secret). |
| `CryptoNugget::new(&seed, role)`                          | Default context.                                      |
| `CryptoNugget::new_with_context(&seed, role, b"app/v1")`  | Domain-separated context (recommended in real apps).  |
| `nug.cifrar(&str)` / `nug.cifrar_bytes(&[u8])`            | Encrypt + ratchet TX. Returns base64 wire-v2 packet.  |
| `nug.descifrar(&str)` / `nug.descifrar_bytes(&str)`       | Decrypt + ratchet RX. Accepts wire v2 and legacy v1 inbound. |
| `nug.cifrar_bytes_with_aad(&[u8], &[u8])`                 | Encrypt binary data and bind external metadata as AAD. |
| `nug.descifrar_bytes_with_aad(&Packet, &[u8])`            | Decrypt a typed packet and verify the expected AAD.   |
| `nug.export_state(&[u8; 32])`                             | Export an encrypted ordered-channel snapshot.         |
| `CryptoNugget::import_state(&bytes, &[u8; 32], context)`  | Import a snapshot, blocked until `mark_resumed()`.    |
| `nug.mark_resumed()`                                      | Explicitly acknowledge resumed snapshot state.        |
| `CryptoNugget::builder(&seed, role).mode(...)`            | Build a specific operation mode.                      |
| `StatelessEnvelope::new(&seed)`                           | Build a stateless envelope for independent messages.  |
| `ReplayWindowChannel::new(&seed, role, 64)`                | Build an out-of-order channel with replay rejection.  |

### Domain separation (do this in real apps)

Two unrelated apps that accidentally share a seed must not be able to read each other. Always pass an app-specific context:

```rust
let mut nug = CryptoNugget::new_with_context(&seed, Role::Initiator, b"my-app/chat/v1");
```

The context feeds the HKDF salt, so a wrong context yields a different key tree and packets fail authentication.

### Binary payloads

Use `cifrar_bytes` / `descifrar_bytes` when the payload is not UTF-8 (serialized structs, files, etc.). Same wire format, same guarantees.

### Authenticated metadata (AAD)

Use AAD when metadata lives outside the encrypted payload but MUST NOT be
tampered with: request IDs, room IDs, message types, tenant IDs, or protocol
version labels. The AAD bytes are authenticated by AES-GCM but are not stored in
the packet, so the receiver must supply the same bytes:

```rust
use cripto_endevs_comunity::{CryptoNugget, MasterSeed, Role};

let seed = MasterSeed::generate();
let mut alice = CryptoNugget::new(&seed, Role::Initiator);
let mut bob = CryptoNugget::new(&seed, Role::Responder);

let aad = b"room:general|message:42";
let packet = alice.cifrar_bytes_with_aad(b"hello", aad).unwrap();
let plaintext = bob.descifrar_bytes_with_aad(&packet, aad).unwrap();

assert_eq!(plaintext, b"hello");
```

If the receiver supplies different AAD, decryption fails with
`Error::Autenticacion` and the RX ratchet does not advance.

### Stateless envelopes

Use `StatelessEnvelope` for independent encrypted blobs where you do not want a
session ratchet: queued jobs, short files, cache entries, or events that may be
read in any order. Each seal uses a fresh nonce and derives a per-message key
with HKDF.

```rust
use cripto_endevs_comunity::{MasterSeed, StatelessEnvelope};

let seed = MasterSeed::generate();
let writer = StatelessEnvelope::new(&seed);
let reader = StatelessEnvelope::new(&seed);

let packet = writer.seal(b"detached payload", b"type:file").unwrap();
let plaintext = reader.open(&packet, b"type:file").unwrap();

assert_eq!(plaintext, b"detached payload");
```

This mode does **not** provide channel ratcheting, ordering, or replay tracking.
If you need those guarantees, use `CryptoNugget` ordered channels instead.

### Replay-window channels

Use `ReplayWindowChannel` only when your transport may reorder packets but you
still need bounded replay rejection. Packets inside the window can arrive out of
order once; repeated packets fail with `Error::Repetido`; packets older than the
window fail with `Error::FueraDeOrden`.

```rust
use cripto_endevs_comunity::{MasterSeed, ReplayWindowChannel, Role};

let seed = MasterSeed::generate();
let mut alice = ReplayWindowChannel::new(&seed, Role::Initiator, 64).unwrap();
let mut bob = ReplayWindowChannel::new(&seed, Role::Responder, 64).unwrap();

let first = alice.seal(b"first", b"").unwrap();
let second = alice.seal(b"second", b"").unwrap();

assert_eq!(bob.open(&second, b"").unwrap(), b"second");
assert_eq!(bob.open(&first, b"").unwrap(), b"first");
```

This mode intentionally does **not** ratchet per message. It trades forward
secrecy for out-of-order tolerance. Use the ordered channel when you need the
ratchet.

### Encrypted state snapshots

Use `export_state` only when you need to persist an ordered channel across a
controlled restart. Snapshots are AES-GCM encrypted and authenticated with a
caller-supplied 32-byte wrap key. After import, sending is blocked until you call
`mark_resumed()` so operators explicitly acknowledge that persisted state is
being reused.

```rust
use cripto_endevs_comunity::{CryptoNugget, MasterSeed, Role};

let seed = MasterSeed::generate();
let wrap_key = [7u8; 32]; // In production: random key from your KMS/secret store.

let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"my-app/v1");
let snapshot = alice.export_state(&wrap_key).unwrap();

let mut restored = CryptoNugget::import_state(&snapshot, &wrap_key, b"my-app/v1").unwrap();
restored.mark_resumed();
```

Do **not** use a password directly as the wrap key. CryptoNugget intentionally
does not include a passphrase KDF; derive or fetch the 32-byte wrap key outside
the crate.

---

## Security model

CryptoNugget is built around **one root secret + symmetric ratchet per direction**.

### Construction

1. `MasterSeed` (32 bytes from `OsRng`) is fed into HKDF-SHA-256 with a salt that includes a stable label and the caller's `context`.
2. HKDF expands two 256-bit keys (`tx-key:a`, `tx-key:b`). The role decides which one is your TX and which is your RX.
3. Every successful `cifrar` rotates the TX key via HKDF; every successful `descifrar` rotates the RX key. Old keys are `zeroize`d.
4. Every packet carries `version || flags || sequence || nonce || ciphertext+tag` in wire v2, with `version`, `flags`, `sequence`, snapshot epoch, and optional caller AAD authenticated as AEAD AAD.

### What that gives you

- **Confidentiality + integrity** of every packet (AES-GCM).
- **Replay resistance** within the channel — a delivered packet's RX key is rotated immediately, so the same bytes won't decrypt again.
- **Order enforcement** — the internal AAD includes the sequence; reordered packets fail authentication against the current RX key.
- **Domain separation** — different `context` ⇒ different keys ⇒ no cross-talk even with the same seed.
- **Memory hygiene** — `Zeroize`/`ZeroizeOnDrop`, no `unsafe`, redacted `Debug` impls.

---

## Threat model

See [`SECURITY.md`](./SECURITY.md) for the full version. Summary:

| Threat                            | Mitigated? |
|-----------------------------------|------------|
| Passive eavesdropping             | Yes — AES-256-GCM |
| Tampering with payload or header  | Yes — AEAD + AAD over `version || flags || sequence` |
| Replay of a delivered packet      | Yes — RX key rotates after success |
| Wrong role / wrong context        | Yes — different derived keys |
| Master seed leakage               | **No — full break.** Seed = root authority. |
| Key exchange / identity / groups  | **Out of scope.** |
| Out-of-order delivery             | **Not supported.** Strict in-order channel. |
| Side-channel attacks              | Inherited from `aes-gcm` and `hkdf`. No additional countermeasures. |

---

## Limitations & non-goals

CryptoNugget is **not** a protocol like Signal or Noise. It deliberately does not implement:

- Diffie-Hellman or any key exchange / handshake.
- Forward secrecy if the seed is compromised. (Per-message ratchet protects only against future compromise of an in-memory key, **not** the root seed.)
- Identity, authentication of peers beyond seed possession, or PKI.
- Group messaging or multi-device sync.
- Out-of-order or lossy delivery in the default ordered channel. Use `ReplayWindowChannel` only if you explicitly accept its weaker forward-secrecy properties.
- Replay tracking for `StatelessEnvelope`. Store packet IDs or hashes yourself if replay matters.
- Persistent state snapshots for the ordered channel are supported, but only with
  a 32-byte wrap key and explicit `mark_resumed()` acknowledgement after import.
- Transport. You bring TCP/HTTP/WebSocket/etc.

If you need any of the above, pair this with a real protocol or pick a different library.

---

## Performance & reliability

- Pure Rust dependencies (`aes-gcm`, `hkdf`, `sha2`, `zeroize`, `base64`).
- Zero `unsafe` (`#![forbid(unsafe_code)]`).
- Per-message overhead: 1 HKDF expand + 1 AES-GCM call + 1 base64 encode/decode + 1 small `Vec` allocation.
- Wire-v2 overhead per packet: 22 bytes header + 16 bytes tag = **38 bytes**, plus base64 expansion (~33%). Legacy inbound v1 has a 21-byte header.
- No background threads, no timers, no I/O.

Reliability properties:

- Strictly typed errors — every failure mode is enumerated in `Error`.
- Authenticated metadata: tampering with `version`, `sequence`, or `nonce` fails as `Error::Autenticacion`.
- Sequence overflow returns `Error::Cifrado` rather than wrapping.
- All-zero seed is rejected (`Error::SemillaInvalida`).

---

## Testing & CI

- **65 tests**: unit, adversarial, packet/AAD, mode/envelope, and replay-window integration coverage.
- Adversarial coverage includes: per-field tampering (version, flags/sequence, nonce, tag), replay, future packets, role confusion, context isolation, binary and empty payloads, AAD mismatch, v1 inbound compatibility, typed packet codecs, and `Debug` redaction.
- CI runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` on Linux/macOS/Windows, and `cargo audit` on every push and PR. See [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

Run locally:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
```

---

## Safe-usage checklist

Before shipping anything that uses CryptoNugget, confirm:

- [ ] Seeds are generated with `MasterSeed::generate()` (or from a verified high-entropy source).
- [ ] Transfer tokens (`export_for_transfer`) are sent over a **secure, ephemeral** channel — never logs, URLs, analytics, screenshots, or persistent storage you don't control.
- [ ] You call `new_with_context` with a stable, app-specific context (e.g., `b"myapp/chat/v1"`).
- [ ] The two sides agree on roles: exactly one `Initiator`, exactly one `Responder`.
- [ ] Your transport delivers packets **in order**. If it can't, you need a different design.
- [ ] You handle `Error::Autenticacion` as a channel-fatal event, not a retry signal. Out-of-order, replayed, or tampered packets all surface as `Autenticacion` and indicate the channel can no longer be trusted in its current state.
- [ ] If you persist state, the wrap key is a random 32-byte key from a KMS or
      equivalent secret store, not a raw passphrase.
- [ ] After `import_state`, you call `mark_resumed()` only after your operator or
      recovery workflow confirms this snapshot should continue the session.
- [ ] You never `Debug`-print or serialize `MasterSeed` or `CryptoNugget` to a sink you don't control. (The `Debug` impls are redacted, but the bytes still live in memory.)
- [ ] You do not depend on backwards compatibility for any wire format produced before 1.0.

---

## Versioning & wire format

Each packet starts with a single `version` byte. CryptoNugget v0.3 emits wire
version `2`; the ordered channel accepts wire version `1` inbound for one
release cycle to support gradual upgrades. Unknown versions return
`Error::VersionNoSoportada`. Until 1.0, both the API and the wire format may
change in minor releases. See [`MIGRATION-0.3.md`](./MIGRATION-0.3.md).

Packet layout:

```
+---------+----------+----------------+-----------+----------------------+
| version | flags    | sequence (u64) | nonce(12) | ciphertext + tag(16) |
+---------+----------+----------------+-----------+----------------------+
   1 byte    1 byte      8 bytes        12 bytes        N + 16 bytes
   |--------- internal AAD ---------|    (AES-GCM authenticates the rest)
```

Flag bit 0 means caller-supplied AAD was bound into authentication. The AAD
bytes are **not** stored in the packet. Then the packet is base64-encoded for
text transports.

---

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)

at your option.

## Author

* **Desarrollador:** ENRODMONTPAR
* **GitHub C#:** [@MASTER-RODRI](https://github.com/MASTER-RODRI/cripto_endevs_comunity_C-)
* **GitHub RUST:** [@MASTER-RODRI](https://github.com/MASTER-RODRI/cripto_endevs_comunity)
* **Crates.io:** [@MASTER-RODRI](https://crates.io/crates/cripto_endevs_comunity)
* **nugget.org:** [@ENRODMONTPAR](https://www.nuget.org/packages/cripto_endevs_comunity)
* **npmjs.com:** [@ENRODMONTPAR](https://www.npmjs.com/package/cripto_endevs_comunity)
**ENRODMONTPAR** — [@MASTER-RODRI](https://github.com/MASTER-RODRI)
