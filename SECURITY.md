# Security Policy

## Reporting a Vulnerability

If you discover a vulnerability in CryptoNugget, **please do not open a public GitHub issue**.

Instead, contact the maintainer privately:

- **GitHub**: open a private security advisory at <https://github.com/MASTER-RODRI/cripto_endevs_comunity/security/advisories/new>
- **Author**: ENRODMONTPAR ([@MASTER-RODRI](https://github.com/MASTER-RODRI))

We aim to acknowledge reports within 7 days and to publish a fix or mitigation within 30 days when feasible.

## Threat Model

CryptoNugget is a small symmetric, authenticated channel between **two parties** that already share a 256-bit master seed.

### What it protects against

- **Passive eavesdropping** of message contents (AES-256-GCM confidentiality).
- **Active tampering** of message contents, header version, sequence number, or nonce (AES-GCM tag + AAD).
- **Replay** of a previously delivered message on the same channel (per-direction symmetric ratchet rotates the receive key after each successful decryption).
- **Bounded replay** in `ReplayWindowChannel` (explicit opt-in): repeated packets inside the configured window are rejected.
- **Cross-domain confusion** between two applications that accidentally share a seed (HKDF salt is bound to a caller-supplied `context`).
- **Wrong-role pairing** (Initiator vs Responder use different derived keys; two Initiators cannot read each other).
- **Authenticated state snapshots** for the ordered channel when callers provide a high-entropy 32-byte wrap key.
- **Memory residue** of key material (`zeroize` on mutate and on drop; `#![forbid(unsafe_code)]`).

### What it does NOT protect against

- **Master seed leakage.** Anyone with the seed can derive the entire session. There is no forward secrecy if the seed is compromised. Treat the seed and any transfer token as a root secret.
- **Key exchange.** CryptoNugget does not perform Diffie-Hellman, PAKE, or any handshake. Seed distribution is the caller's responsibility and must use a secure, ephemeral channel.
- **Identity / authentication of peers.** Anyone who holds the seed is, by definition, "the peer".
- **Out-of-order delivery in the default ordered channel.** A lost or reordered packet desynchronizes the receiver permanently. `ReplayWindowChannel` supports bounded out-of-order delivery, but with weaker security properties.
- **Forward secrecy in `ReplayWindowChannel`.** Replay-window mode uses stable per-direction keys so it can decrypt packets out of order. It does **not** provide the per-message ratchet property of the default ordered channel. If an in-memory replay-window key leaks, packets protected by that direction key are compromised.
- **Passphrase-based persistence.** `export_state` requires a raw 32-byte wrap key. CryptoNugget does not run Argon2, PBKDF2, scrypt, or any other password KDF in-crate. If humans type a password, derive the wrap key outside this crate before calling `export_state` or `import_state`.
- **Multi-device or transport security.**
- **Side-channel attacks** beyond what `aes-gcm` and `hkdf` provide upstream.
- **Compromise of the host system** (memory dumps from a privileged attacker, malicious OS, etc.).

### Security boundary

The security of every CryptoNugget session reduces to **the secrecy of the `MasterSeed`** plus the soundness of `aes-gcm`, `hkdf-sha256`, and `OsRng`. If any of those break, the session breaks.

### State snapshot handling

Snapshots exported with `CryptoNugget::export_state` contain live channel key
material encrypted with AES-256-GCM. Treat them as sensitive encrypted backups:

- The wrap key must be exactly 32 random bytes from a KMS or equivalent secret
  store.
- Do not pass user passwords directly as wrap keys. Use a memory-hard KDF outside
  this crate if a passphrase is unavoidable.
- `import_state` binds snapshots to the caller-supplied context and returns
  `Error::Autenticacion` for the wrong wrap key or wrong context.
- Imported states cannot send until `mark_resumed()` is called. This is an
  operator acknowledgement guard against accidental replay-on-restore workflows.

## Supported Versions

Only the latest published `0.1.x` release receives security fixes. The crate is pre-1.0 and the wire format may evolve in future minor versions. The on-the-wire `version` byte is reserved for explicit format migrations.

## Cryptographic Inventory

| Primitive          | Purpose                                  | Crate           |
|--------------------|------------------------------------------|-----------------|
| AES-256-GCM        | Authenticated encryption of payloads     | `aes-gcm 0.10`  |
| HKDF-SHA-256       | Initial key derivation + ratchet step    | `hkdf 0.12`     |
| SHA-256            | KDF hash function                        | `sha2 0.10`     |
| OS CSPRNG          | Master seed and per-message nonces       | `rand::OsRng`   |
| OS CSPRNG          | Snapshot nonces                          | `rand::OsRng`   |
| `zeroize`          | Wipe key material on mutate / drop       | `zeroize 1.8`   |
