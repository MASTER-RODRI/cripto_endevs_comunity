use cripto_endevs_comunity::{CryptoNugget, Error, MasterSeed, Role};

fn wrap_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn imported_state_requires_explicit_resume_ack_before_sending() {
    let seed = MasterSeed::generate();
    let wrap = wrap_key(0x42);
    let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"pr5/app");

    let snapshot = alice.export_state(&wrap).unwrap();
    let mut restored = CryptoNugget::import_state(&snapshot, &wrap, b"pr5/app").unwrap();

    assert!(matches!(
        restored.cifrar("blocked until operator ack"),
        Err(Error::EstadoSinReanudar)
    ));
}

#[test]
fn restored_state_can_resume_after_ack_and_peer_accepts_next_packet() {
    let seed = MasterSeed::generate();
    let wrap = wrap_key(0x24);
    let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"pr5/restore");
    let mut bob = CryptoNugget::new_with_context(&seed, Role::Responder, b"pr5/restore");

    let first = alice.cifrar("before snapshot").unwrap();
    assert_eq!(bob.descifrar(&first).unwrap(), "before snapshot");

    let snapshot = alice.export_state(&wrap).unwrap();
    let mut restored = CryptoNugget::import_state(&snapshot, &wrap, b"pr5/restore").unwrap();
    restored.mark_resumed();

    let second = restored.cifrar("after restore").unwrap();
    assert_eq!(bob.descifrar(&second).unwrap(), "after restore");
}

#[test]
fn wrong_wrap_key_fails_authentication() {
    let seed = MasterSeed::generate();
    let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"pr5/wrap");
    let snapshot = alice.export_state(&wrap_key(0x10)).unwrap();

    assert!(matches!(
        CryptoNugget::import_state(&snapshot, &wrap_key(0x11), b"pr5/wrap"),
        Err(Error::Autenticacion)
    ));
}

#[test]
fn context_mismatch_is_rejected() {
    let seed = MasterSeed::generate();
    let wrap = wrap_key(0x33);
    let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"pr5/context-a");
    let snapshot = alice.export_state(&wrap).unwrap();

    assert!(matches!(
        CryptoNugget::import_state(&snapshot, &wrap, b"pr5/context-b"),
        Err(Error::Autenticacion)
    ));
}

#[test]
fn snapshot_has_versioned_magic_layout_and_is_authenticated() {
    let seed = MasterSeed::generate();
    let wrap = wrap_key(0x55);
    let mut alice = CryptoNugget::new_with_context(&seed, Role::Initiator, b"pr5/layout");
    let mut snapshot = alice.export_state(&wrap).unwrap();

    assert_eq!(&snapshot[..4], b"CNST");
    assert_eq!(snapshot[4], 1);
    assert!(snapshot.len() > 4 + 1 + 12 + 16);

    let last = snapshot.len() - 1;
    snapshot[last] ^= 0x01;
    assert!(matches!(
        CryptoNugget::import_state(&snapshot, &wrap, b"pr5/layout"),
        Err(Error::Autenticacion)
    ));
}
