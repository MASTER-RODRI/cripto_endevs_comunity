//! PR3 — Mode enum, Builder, and StatelessEnvelope.

use cripto_endevs_comunity::{CryptoNugget, Error, MasterSeed, Mode, Role, StatelessEnvelope};

#[test]
fn builder_default_ordered_channel_matches_existing_constructor() {
    let seed = MasterSeed::generate();
    let mut alice = CryptoNugget::builder(&seed, Role::Initiator)
        .build_ordered()
        .unwrap();
    let mut bob = CryptoNugget::builder(&seed, Role::Responder)
        .build_ordered()
        .unwrap();

    let pkt = alice.cifrar("builder ordered").unwrap();
    assert_eq!(bob.descifrar(&pkt).unwrap(), "builder ordered");
}

#[test]
fn builder_can_construct_stateless_envelope() {
    let seed = MasterSeed::generate();
    let alice = CryptoNugget::builder(&seed, Role::Initiator)
        .mode(Mode::StatelessEnvelope)
        .build_stateless_envelope()
        .unwrap();
    let bob = CryptoNugget::builder(&seed, Role::Responder)
        .mode(Mode::StatelessEnvelope)
        .build_stateless_envelope()
        .unwrap();

    let packet = alice.seal(b"one shot", b"kind:event").unwrap();
    assert_eq!(bob.open(&packet, b"kind:event").unwrap(), b"one shot");
}

#[test]
fn builder_rejects_wrong_build_method_for_mode() {
    let seed = MasterSeed::generate();
    let err = CryptoNugget::builder(&seed, Role::Initiator)
        .mode(Mode::StatelessEnvelope)
        .build_ordered()
        .unwrap_err();
    assert!(matches!(err, Error::ModoInvalido));
}

#[test]
fn stateless_envelope_roundtrip_without_mutating_session_state() {
    let seed = MasterSeed::generate();
    let alice = StatelessEnvelope::new(&seed);
    let bob = StatelessEnvelope::new(&seed);

    let first = alice.seal(b"first", b"").unwrap();
    let second = alice.seal(b"second", b"").unwrap();

    assert_eq!(bob.open(&second, b"").unwrap(), b"second");
    assert_eq!(bob.open(&first, b"").unwrap(), b"first");
    assert_eq!(bob.open(&first, b"").unwrap(), b"first");
}

#[test]
fn stateless_envelope_rejects_aad_mismatch() {
    let seed = MasterSeed::generate();
    let alice = StatelessEnvelope::new(&seed);
    let bob = StatelessEnvelope::new(&seed);

    let packet = alice.seal(b"secret", b"tenant:A").unwrap();
    let result = bob.open(&packet, b"tenant:B");

    assert!(matches!(result, Err(Error::Autenticacion)));
}

#[test]
fn stateless_envelope_context_isolation() {
    let seed = MasterSeed::generate();
    let alice = StatelessEnvelope::new_with_context(&seed, b"app-a/v1");
    let bob = StatelessEnvelope::new_with_context(&seed, b"app-b/v1");

    let packet = alice.seal(b"secret", b"").unwrap();
    assert!(matches!(bob.open(&packet, b""), Err(Error::Autenticacion)));
}

#[test]
fn stateless_envelope_rejects_legacy_v1_packet() {
    let seed = MasterSeed::generate();
    let envelope = StatelessEnvelope::new(&seed);
    let mut packet = envelope.seal(b"v2", b"").unwrap();
    packet.version = 1;

    assert!(matches!(
        envelope.open(&packet, b""),
        Err(Error::VersionNoSoportada(1))
    ));
}
