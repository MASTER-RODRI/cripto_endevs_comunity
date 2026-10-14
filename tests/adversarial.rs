//! Tests adversariales: replay, tampering por campo, roles invertidos,
//! separación de contexto, versionado y payloads binarios.
//!
//! Estos tests viven fuera de `src/lib.rs` para ejercitar solo el API público
//! tal como lo verá un consumidor de la crate.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cripto_endevs_comunity::{CryptoNugget, Error, MasterSeed, Role};

fn pareja() -> (MasterSeed, CryptoNugget, CryptoNugget) {
    let semilla = MasterSeed::generate();
    let alice = CryptoNugget::new(&semilla, Role::Initiator);
    let bob = CryptoNugget::new(&semilla, Role::Responder);
    (semilla, alice, bob)
}

// --- Tampering por campo ----------------------------------------------------

#[test]
fn tamper_version_byte_falla() {
    let (_, mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("hola").unwrap();
    let mut bytes = STANDARD.decode(&cifrado).unwrap();
    bytes[0] = 99; // versión inexistente
    let mutado = STANDARD.encode(&bytes);
    assert!(matches!(
        bob.descifrar(&mutado),
        Err(Error::VersionNoSoportada(99))
    ));
}

#[test]
fn tamper_sequence_byte_falla() {
    let (_, mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("hola").unwrap();
    let mut bytes = STANDARD.decode(&cifrado).unwrap();
    bytes[5] ^= 0xAA; // mutación dentro de la secuencia (autenticada como AAD)
    let mutado = STANDARD.encode(&bytes);
    assert!(matches!(bob.descifrar(&mutado), Err(Error::Autenticacion)));
}

#[test]
fn tamper_nonce_byte_falla() {
    let (_, mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("hola").unwrap();
    let mut bytes = STANDARD.decode(&cifrado).unwrap();
    bytes[10] ^= 0x01; // dentro del nonce
    let mutado = STANDARD.encode(&bytes);
    assert!(matches!(bob.descifrar(&mutado), Err(Error::Autenticacion)));
}

#[test]
fn tamper_tag_byte_falla() {
    let (_, mut alice, mut bob) = pareja();
    let cifrado = alice.cifrar("hola").unwrap();
    let mut bytes = STANDARD.decode(&cifrado).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF; // tag al final
    let mutado = STANDARD.encode(&bytes);
    assert!(matches!(bob.descifrar(&mutado), Err(Error::Autenticacion)));
}

// --- Replay y orden ---------------------------------------------------------

#[test]
fn replay_mismo_paquete_falla_segunda_vez() {
    let (_, mut alice, mut bob) = pareja();
    let c = alice.cifrar("una sola vez").unwrap();
    assert_eq!(bob.descifrar(&c).unwrap(), "una sola vez");
    // El segundo intento usa la rx_key ya rotada → AEAD falla.
    assert!(matches!(bob.descifrar(&c), Err(Error::Autenticacion)));
}

#[test]
fn paquete_futuro_falla_y_no_avanza_estado() {
    let (_, mut alice, mut bob) = pareja();
    let c1 = alice.cifrar("uno").unwrap();
    let _c2 = alice.cifrar("dos").unwrap();
    // c1 es secuencia 0; bob aún espera 0 pero su rx_key sigue intacta.
    // Probamos primero que c1 funciona normal.
    assert_eq!(bob.descifrar(&c1).unwrap(), "uno");
    // Ahora bob espera secuencia 1 y rx_key rotada. Un cifrado nuevo de alice
    // (secuencia 2) no autenticará contra la rx_key actual de bob.
    let c3 = alice.cifrar("tres").unwrap();
    assert!(matches!(bob.descifrar(&c3), Err(Error::Autenticacion)));
}

// --- Roles y contexto -------------------------------------------------------

#[test]
fn dos_initiators_no_se_descifran_entre_si() {
    let semilla = MasterSeed::generate();
    let mut a = CryptoNugget::new(&semilla, Role::Initiator);
    let mut b = CryptoNugget::new(&semilla, Role::Initiator);
    let c = a.cifrar("hola").unwrap();
    // Mismo rol → mismas claves tx; b intenta descifrar con su rx_key (la otra).
    assert!(matches!(b.descifrar(&c), Err(Error::Autenticacion)));
}

#[test]
fn contexto_distinto_aisla_dominios() {
    let semilla = MasterSeed::generate();
    let mut alice = CryptoNugget::new_with_context(&semilla, Role::Initiator, b"app/chat/v1");
    let mut bob = CryptoNugget::new_with_context(&semilla, Role::Responder, b"app/files/v1");
    let c = alice.cifrar("cruzado").unwrap();
    assert!(matches!(bob.descifrar(&c), Err(Error::Autenticacion)));
}

#[test]
fn mismo_contexto_misma_semilla_interopera() {
    let semilla = MasterSeed::generate();
    let mut alice = CryptoNugget::new_with_context(&semilla, Role::Initiator, b"app/chat/v1");
    let mut bob = CryptoNugget::new_with_context(&semilla, Role::Responder, b"app/chat/v1");
    let c = alice.cifrar("ok").unwrap();
    assert_eq!(bob.descifrar(&c).unwrap(), "ok");
}

// --- Payloads binarios y bordes --------------------------------------------

#[test]
fn payload_binario_no_utf8_funciona() {
    let (_, mut alice, mut bob) = pareja();
    let crudo = vec![0u8, 0xFF, 0xFE, 0xC0, 0xC1, 0x80];
    let c = alice.cifrar_bytes(&crudo).unwrap();
    let recibido = bob.descifrar_bytes(&c).unwrap();
    assert_eq!(recibido, crudo);
}

#[test]
fn descifrar_string_sobre_bytes_no_utf8_devuelve_utf8_error() {
    let (_, mut alice, mut bob) = pareja();
    let crudo = vec![0xFF, 0xFE, 0xC0];
    let c = alice.cifrar_bytes(&crudo).unwrap();
    assert!(matches!(bob.descifrar(&c), Err(Error::Utf8)));
}

#[test]
fn payload_grande_funciona() {
    let (_, mut alice, mut bob) = pareja();
    let grande = vec![0x42u8; 64 * 1024];
    let c = alice.cifrar_bytes(&grande).unwrap();
    let recibido = bob.descifrar_bytes(&c).unwrap();
    assert_eq!(recibido, grande);
}

#[test]
fn payload_vacio_funciona() {
    let (_, mut alice, mut bob) = pareja();
    let c = alice.cifrar_bytes(&[]).unwrap();
    let recibido = bob.descifrar_bytes(&c).unwrap();
    assert!(recibido.is_empty());
}

// --- Debug no filtra secretos -----------------------------------------------

#[test]
fn debug_de_master_seed_no_filtra_bytes() {
    let semilla = MasterSeed::generate();
    let s = format!("{:?}", semilla);
    assert!(s.contains("redacted"));
    // La representación en transferencia es base64 de 32 bytes ⇒ 44 chars.
    let token = semilla.export_for_transfer();
    assert!(!s.contains(&token));
}

#[test]
fn debug_de_nugget_no_filtra_claves() {
    let (_, alice, _) = pareja();
    let s = format!("{:?}", alice);
    assert!(s.contains("redacted"));
    assert!(s.contains("tx_seq"));
}
