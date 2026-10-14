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
    assert_eq!(snapshot[4], 2); // SNAPSHOT_VERSION_V2 (incluye epoch y SHA-256 transcript)
    assert!(snapshot.len() > 4 + 1 + 12 + 16);

    let last = snapshot.len() - 1;
    snapshot[last] ^= 0x01;
    assert!(matches!(
        CryptoNugget::import_state(&snapshot, &wrap, b"pr5/layout"),
        Err(Error::Autenticacion)
    ));
}

#[test]
fn dual_slot_atomic_disk_save_and_recover() {
    use cripto_endevs_comunity::DualSlotContainer;

    let wrap = wrap_key(0x77);
    let mut container = DualSlotContainer::new();
    container.commit_state(b"generation-1-data", &wrap).unwrap();

    let test_path = std::env::temp_dir().join(format!("test_dualslot_{}.bin", std::process::id()));
    container.save_atomic(&test_path).unwrap();

    let loaded = DualSlotContainer::load_from_file(&test_path).unwrap();
    let (generation, data) = loaded.recover_latest_valid(&wrap).unwrap();
    assert_eq!(generation, 1);
    assert_eq!(data, b"generation-1-data");

    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn wal_file_append_and_truncate_recovery() {
    use cripto_endevs_comunity::{ChronoWalJournal, Packet, WIRE_VERSION_V3};

    let test_path = std::env::temp_dir().join(format!("test_wal_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&test_path);

    let mut wal = ChronoWalJournal::new();
    let p1 = Packet {
        version: WIRE_VERSION_V3,
        flags: 0,
        node_id: 1,
        epoch: 1,
        sequence: 1,
        timestamp_ms: 1000,
        nonce: [1u8; 12],
        ciphertext: vec![0xAA; 32],
    };
    let p2 = Packet {
        version: WIRE_VERSION_V3,
        flags: 0,
        node_id: 1,
        epoch: 1,
        sequence: 2,
        timestamp_ms: 1005,
        nonce: [2u8; 12],
        ciphertext: vec![0xBB; 32],
    };

    wal.append_to_file(&test_path, &p1).unwrap();
    wal.append_to_file(&test_path, &p2).unwrap();

    // Simular corte de luz a mitad de append escribiendo bytes truncados al final del archivo
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&test_path)
            .unwrap();
        file.write_all(b"CNWL\x00\x00\x00\x50\x99\x99incomplete-tail-bytes")
            .unwrap();
        file.sync_all().unwrap();
    }

    let (recovered_wal, report) = ChronoWalJournal::recover_from_file(&test_path).unwrap();
    assert_eq!(report.packets.len(), 2);
    assert!(report.had_truncated_tail);
    assert_eq!(recovered_wal.frames_count(), 2);

    let _ = std::fs::remove_file(&test_path);
}
