//! PR4 — ReplayWindowChannel.

use cripto_endevs_comunity::{CryptoNugget, Error, MasterSeed, Mode, ReplayWindowChannel, Role};

fn pareja(window: u64) -> (ReplayWindowChannel, ReplayWindowChannel) {
    let seed = MasterSeed::generate();
    let alice = ReplayWindowChannel::new(&seed, Role::Initiator, window).unwrap();
    let bob = ReplayWindowChannel::new(&seed, Role::Responder, window).unwrap();
    (alice, bob)
}

#[test]
fn replay_window_accepts_out_of_order_within_window() {
    let (mut alice, mut bob) = pareja(64);
    let p0 = alice.seal(b"zero", b"").unwrap();
    let p1 = alice.seal(b"one", b"").unwrap();
    let p2 = alice.seal(b"two", b"").unwrap();

    assert_eq!(bob.open(&p2, b"").unwrap(), b"two");
    assert_eq!(bob.open(&p0, b"").unwrap(), b"zero");
    assert_eq!(bob.open(&p1, b"").unwrap(), b"one");
}

#[test]
fn replay_window_rejects_repeated_packet() {
    let (mut alice, mut bob) = pareja(64);
    let packet = alice.seal(b"once", b"").unwrap();

    assert_eq!(bob.open(&packet, b"").unwrap(), b"once");
    assert!(matches!(bob.open(&packet, b""), Err(Error::Repetido)));
}

#[test]
fn replay_window_rejects_below_window() {
    let (mut alice, mut bob) = pareja(4);
    let packets: Vec<_> = (0..6)
        .map(|i| alice.seal(format!("msg-{i}").as_bytes(), b"").unwrap())
        .collect();

    assert_eq!(bob.open(&packets[5], b"").unwrap(), b"msg-5");
    assert!(matches!(
        bob.open(&packets[0], b""),
        Err(Error::FueraDeOrden)
    ));
}

#[test]
fn replay_window_aad_mismatch_does_not_mark_seen() {
    let (mut alice, mut bob) = pareja(64);
    let packet = alice.seal(b"secret", b"tenant:A").unwrap();

    assert!(matches!(
        bob.open(&packet, b"tenant:B"),
        Err(Error::Autenticacion)
    ));
    assert_eq!(bob.open(&packet, b"tenant:A").unwrap(), b"secret");
}

#[test]
fn replay_window_context_isolation() {
    let seed = MasterSeed::generate();
    let mut alice =
        ReplayWindowChannel::new_with_context(&seed, Role::Initiator, b"a/v1", 64).unwrap();
    let mut bob =
        ReplayWindowChannel::new_with_context(&seed, Role::Responder, b"b/v1", 64).unwrap();

    let packet = alice.seal(b"secret", b"").unwrap();
    assert!(matches!(bob.open(&packet, b""), Err(Error::Autenticacion)));
}

#[test]
fn replay_window_rejects_invalid_window_sizes() {
    let seed = MasterSeed::generate();
    assert!(matches!(
        ReplayWindowChannel::new(&seed, Role::Initiator, 0),
        Err(Error::ModoInvalido)
    ));
    assert!(matches!(
        ReplayWindowChannel::new(&seed, Role::Initiator, 129),
        Err(Error::ModoInvalido)
    ));
}

#[test]
fn builder_can_construct_replay_window_channel() {
    let seed = MasterSeed::generate();
    let mut alice = CryptoNugget::builder(&seed, Role::Initiator)
        .mode(Mode::ReplayWindowChannel { window: 64 })
        .build_replay_window()
        .unwrap();
    let mut bob = CryptoNugget::builder(&seed, Role::Responder)
        .mode(Mode::ReplayWindowChannel { window: 64 })
        .build_replay_window()
        .unwrap();

    let packet = alice.seal(b"builder", b"").unwrap();
    assert_eq!(bob.open(&packet, b"").unwrap(), b"builder");
}

#[test]
fn replay_window_debug_redacts_keys() {
    let seed = MasterSeed::generate();
    let channel = ReplayWindowChannel::new(&seed, Role::Initiator, 64).unwrap();
    let debug = format!("{channel:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(&seed.export_for_transfer()));
}
