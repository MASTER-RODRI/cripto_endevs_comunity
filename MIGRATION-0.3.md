# Migration guide: CryptoNugget 0.3

CryptoNugget 0.3 introduces the wire-v2 packet format, a typed `Packet` API, and optional caller-supplied AAD.

## What changes

- New outbound packets use `version = 2`.
- The header now includes a `flags` byte: `version || flags || sequence || nonce || ciphertext+tag`.
- Flag bit `0` means caller AAD was authenticated.
- Wire-v1 packets remain accepted inbound by `CryptoNugget` for one release cycle.
- Unknown versions still fail with `Error::VersionNoSoportada`.

## Existing callers

If you only use `cifrar`, `descifrar`, `cifrar_bytes`, and `descifrar_bytes`, no source change is required:

```rust
let packet_base64 = alice.cifrar("hello")?;
let plaintext = bob.descifrar(&packet_base64)?;
```

The packet emitted by `cifrar*` is now wire v2 with `flags = 0`.

## Typed packets

Use `Packet` when your transport or storage layer wants binary control instead of an opaque base64 string:

```rust
let packet = alice.cifrar_bytes_with_aad(b"hello", b"")?;
let bytes = packet.to_bytes();
let decoded = cripto_endevs_comunity::Packet::from_bytes(&bytes)?;
let plaintext = bob.descifrar_bytes_with_aad(&decoded, b"")?;
```

## Adding AAD

AAD is for metadata that is already available to both sides and must be protected against tampering, but should not be encrypted inside the payload.

Good AAD examples:

- room/channel ID
- message type
- tenant ID
- request ID
- protocol version label

Both sides must supply the exact same bytes:

```rust
let aad = b"room:general|type:chat-message";
let packet = alice.cifrar_bytes_with_aad(b"hello", aad)?;
let plaintext = bob.descifrar_bytes_with_aad(&packet, aad)?;
```

If the receiver supplies different AAD, decryption returns `Error::Autenticacion` and the receiver state does not advance.

## Compatibility window

Wire v1 inbound compatibility exists only to make rolling upgrades safer. Do not generate new v1 packets from 0.3 code. Plan to remove v1 inbound support before 1.0 unless a later release states otherwise.

## Security notes

- AAD bytes are authenticated but not encrypted.
- AAD bytes are not carried inside the packet; your application must transmit or reconstruct them separately.
- Changing AAD semantics is a protocol change for your app. Version your AAD format deliberately.
