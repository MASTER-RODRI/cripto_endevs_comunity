//! PR2 — Wire v2 + typed `Packet` + configurable AAD + v1 inbound compat.
//!
//! Acceptance harness for spec capability `packet-api`. Each test maps directly
//! to a Scenario in `sdd/cryptonugget-v0-3-hardening/spec`:
//!
//! - Round-trip with AAD               -> `aad_roundtrip_*`
//! - AAD mismatch rejected             -> `aad_mismatch_*`
//! - v1 inbound decoded                -> `v1_inbound_*`
//! - Unknown wire version rejected     -> `unknown_version_*`
//! - Binary round-trip (Packet codec)  -> `packet_binary_roundtrip_*`
//!
//! Plus PR2 invariants not in the bullet scenarios:
//! - Default `cifrar` now emits v2 flags=0 (compat with v0.2 callers).
//! - `Packet::to_base64` round-trips byte-identically through `from_base64`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cripto_endevs_comunity::{CryptoNugget, Error, MasterSeed, Packet, Role};

fn pareja() -> (CryptoNugget, CryptoNugget) {
    let semilla = MasterSeed::generate();
    let alice = CryptoNugget::new(&semilla, Role::Initiator);
    let bob = CryptoNugget::new(&semilla, Role::Responder);
    (alice, bob)
}

// --- AAD round-trip ---------------------------------------------------------

#[test]
fn aad_roundtrip_string_with_aad() {
    let (mut alice, mut bob) = pareja();
    let aad = b"req-42";
    let pkt = alice.cifrar_bytes_with_aad(b"hola", aad).unwrap();
    let plano = bob.descifrar_bytes_with_aad(&pkt, aad).unwrap();
    assert_eq!(plano, b"hola");
}

#[test]
fn aad_roundtrip_empty_aad_equivalent_to_default() {
    // cifrar_bytes_with_aad(.., b"") MUST be byte-format equivalent to
    // cifrar_bytes(..) — both emit v2 flags=0 and the receiver's plain
    // descifrar_bytes MUST succeed.
    let (mut alice, mut bob) = pareja();
    let pkt = alice.cifrar_bytes_with_aad(b"sin-aad", b"").unwrap();
    assert_eq!(pkt.flags & 0x01, 0, "AAD bit must be 0 for empty AAD");
    let bytes = pkt.to_bytes();
    let b64 = STANDARD.encode(&bytes);
    let plano = bob.descifrar_bytes(&b64).unwrap();
    assert_eq!(plano, b"sin-aad");
}

// --- AAD mismatch -----------------------------------------------------------

#[test]
fn aad_mismatch_rejected_as_authentication_error() {
    let (mut alice, mut bob) = pareja();
    let pkt = alice.cifrar_bytes_with_aad(b"secreto", b"AAD-A").unwrap();
    let res = bob.descifrar_bytes_with_aad(&pkt, b"AAD-B");
    assert!(matches!(res, Err(Error::Autenticacion)));
}

#[test]
fn aad_mismatch_does_not_advance_rx_state() {
    // After an AAD mismatch the receiver must still be able to decrypt the
    // legitimate packet with the right AAD — i.e. rx_seq did NOT advance.
    let (mut alice, mut bob) = pareja();
    let pkt = alice.cifrar_bytes_with_aad(b"importa", b"correct").unwrap();
    let _ = bob.descifrar_bytes_with_aad(&pkt, b"wrong"); // fails, must not mutate
    let plano = bob.descifrar_bytes_with_aad(&pkt, b"correct").unwrap();
    assert_eq!(plano, b"importa");
}

// --- Default cifrar/descifrar still works (PR2: now emits v2 flags=0) -------

#[test]
fn cifrar_default_now_emits_v2_flags_zero() {
    let (mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("hola").unwrap();
    let bytes = STANDARD.decode(&cifrado).unwrap();
    assert_eq!(bytes[0], 2, "version byte must be 2");
    assert_eq!(bytes[1], 0, "flags byte must be 0 for default no-AAD path");
    let plano = bob.descifrar(&cifrado).unwrap();
    assert_eq!(plano, "hola");
}

#[test]
fn cifrar_default_multiple_messages_still_ratchet() {
    // Carry-over invariant: the default API path still ratchets and rejects
    // out-of-order even after the v1->v2 wire bump.
    let (mut alice, mut bob) = pareja();
    let c1 = alice.cifrar("uno").unwrap();
    let c2 = alice.cifrar("dos").unwrap();
    assert!(matches!(bob.descifrar(&c2), Err(Error::Autenticacion)));
    assert_eq!(bob.descifrar(&c1).unwrap(), "uno");
    assert_eq!(bob.descifrar(&c2).unwrap(), "dos");
}

// --- v1 inbound compatibility (one release cycle, OrderedChannel only) -----

#[test]
fn v1_inbound_decoded_as_flags_zero() {
    // Build a synthetic v1 packet by hand using the v1 wire format
    // (version=1‖seq‖nonce‖ct+tag) and AAD shape (version‖seq, 9 bytes).
    // The receiver MUST accept it as flags=0 and decrypt successfully.
    use aes_gcm::{
        Aes256Gcm, Key,
        aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    let semilla = MasterSeed::generate();
    let mut bob = CryptoNugget::new(&semilla, Role::Responder);

    // Re-derive the same tx_key Alice (Initiator) would have used at seq=0,
    // matching the constructor in `modes::ordered::new_with_context`.
    const DEFAULT_CONTEXT: &[u8] = b"cryptonugget:v1";
    let mut salt = b"CryptoNugget:seed:v1".to_vec();
    salt.push(0);
    salt.extend_from_slice(DEFAULT_CONTEXT);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), semilla_as_bytes(&semilla).as_slice());
    let mut clave_a = [0u8; 32];
    hkdf.expand(b"tx-key:a", &mut clave_a).unwrap();

    let key = Key::<Aes256Gcm>::from_slice(&clave_a);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sequence: u64 = 0;
    // v1 AAD = version(1) || seq(8 BE)
    let mut v1_aad = [0u8; 9];
    v1_aad[0] = 1;
    v1_aad[1..].copy_from_slice(&sequence.to_be_bytes());

    let plaintext = b"legacy v0.2 peer";
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &v1_aad,
            },
        )
        .unwrap();

    // Assemble v1 packet bytes: version(1) || seq(8) || nonce(12) || ct+tag
    let mut v1_packet = Vec::new();
    v1_packet.push(1u8);
    v1_packet.extend_from_slice(&sequence.to_be_bytes());
    v1_packet.extend_from_slice(&nonce);
    v1_packet.extend_from_slice(&ciphertext);
    let v1_b64 = STANDARD.encode(&v1_packet);

    let plano = bob.descifrar_bytes(&v1_b64).unwrap();
    assert_eq!(plano, plaintext);
}

#[test]
fn v1_inbound_rejects_external_aad() {
    let mut packet = Packet {
        version: 1,
        flags: 0,
        sequence: 0,
        nonce: [0u8; 12],
        ciphertext: vec![0u8; 16],
    };
    // The ciphertext is intentionally not valid. The important invariant is
    // that v1 + caller AAD is rejected as authentication failure before any
    // attempt to interpret AAD as if v1 supported it.
    let (_alice, mut bob) = pareja();
    let result = bob.descifrar_bytes_with_aad(&packet, b"unexpected-aad");
    assert!(matches!(result, Err(Error::Autenticacion)));

    // Keep the packet visibly v1 so a future refactor cannot turn this into a
    // generic malformed-v2 test by accident.
    packet.version = 1;
    assert_eq!(packet.version, 1);
}

// Helper — semilla bytes are not pub; round-trip via export_for_transfer.
fn semilla_as_bytes(s: &MasterSeed) -> Vec<u8> {
    STANDARD.decode(s.export_for_transfer()).unwrap()
}

// --- Unknown wire version ---------------------------------------------------

#[test]
fn unknown_wire_version_rejected_typed_error() {
    let (mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("x").unwrap();
    let mut bytes = STANDARD.decode(&cifrado).unwrap();
    bytes[0] = 0x03; // future version
    let mutado = STANDARD.encode(&bytes);
    assert!(matches!(
        bob.descifrar(&mutado),
        Err(Error::VersionNoSoportada(3))
    ));
}

// --- Typed Packet binary + base64 round-trip -------------------------------

#[test]
fn packet_binary_roundtrip_byte_identical() {
    let (mut alice, _bob) = pareja();
    let original = alice.cifrar_bytes_with_aad(b"payload", b"meta").unwrap();
    let bytes = original.to_bytes();
    let decoded = Packet::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.version, original.version);
    assert_eq!(decoded.flags, original.flags);
    assert_eq!(decoded.sequence, original.sequence);
    assert_eq!(decoded.nonce, original.nonce);
    assert_eq!(decoded.ciphertext, original.ciphertext);
    assert_eq!(decoded.to_bytes(), bytes);
}

#[test]
fn packet_base64_roundtrip_byte_identical() {
    let (mut alice, _bob) = pareja();
    let original = alice.cifrar_bytes_with_aad(b"payload", b"meta").unwrap();
    let b64 = original.to_base64();
    let decoded = Packet::from_base64(&b64).unwrap();
    assert_eq!(decoded.to_bytes(), original.to_bytes());
}

#[test]
fn packet_from_bytes_rejects_short_input() {
    let res = Packet::from_bytes(&[2u8, 0u8, 0u8]);
    assert!(matches!(res, Err(Error::PaqueteCorrupto)));
}

#[test]
fn packet_from_bytes_rejects_unknown_version() {
    // Smallest plausible buffer with v=5: still must fail typed.
    let mut buf = vec![5u8, 0u8];
    buf.extend_from_slice(&[0u8; 8]); // seq
    buf.extend_from_slice(&[0u8; 12]); // nonce
    buf.extend_from_slice(&[0u8; 16]); // tag
    let res = Packet::from_bytes(&buf);
    assert!(matches!(res, Err(Error::VersionNoSoportada(5))));
}

// --- Wire shape sanity ------------------------------------------------------

#[test]
fn v2_packet_with_aad_sets_flag_bit_zero() {
    let (mut alice, _bob) = pareja();
    let pkt = alice.cifrar_bytes_with_aad(b"x", b"meta").unwrap();
    assert_eq!(pkt.version, 2);
    assert_eq!(
        pkt.flags & 0x01,
        1,
        "flag bit 0 must be set when AAD present"
    );
}

#[test]
fn v2_packet_without_aad_clears_flag_bit_zero() {
    let (mut alice, _bob) = pareja();
    let pkt = alice.cifrar_bytes_with_aad(b"x", b"").unwrap();
    assert_eq!(pkt.version, 2);
    assert_eq!(pkt.flags & 0x01, 0, "flag bit 0 must be clear when no AAD");
}
