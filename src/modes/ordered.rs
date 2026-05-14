//! Canal **ordenado** ratcheado entre dos partes.
//!
//! PR2 (v0.3 hardening):
//! - Default outbound wire bumped v1→v2 vía [`crate::Packet`].
//! - Nuevo API con AAD configurable: [`CryptoNugget::cifrar_bytes_with_aad`] y
//!   [`CryptoNugget::descifrar_bytes_with_aad`].
//! - Inbound v1 sigue aceptado un ciclo de release para migración gradual.
//! - El API público v0.2 (`cifrar`, `cifrar_bytes`, `descifrar`,
//!   `descifrar_bytes`) se conserva: los métodos sin AAD delegan en la ruta
//!   con AAD vacío y emiten v2 con `flags=0`, byte-equivalente al camino
//!   sin AAD.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::packet::{
    FLAG_AAD_PRESENT, NONCE_LEN, Packet, WIRE_VERSION_V1, WIRE_VERSION_V2, build_internal_aad_v1,
    build_internal_aad_v2_with_epoch,
};
use crate::seed::MasterSeed;

const DEFAULT_CONTEXT: &[u8] = b"cryptonugget:v1";

/// Rol explícito del participante dentro del canal.
///
/// Evita el API frágil `true/false`, donde invertir un booleano rompe la sesión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Primer participante: cifra con la clave A y descifra con la B.
    Initiator,
    /// Segundo participante: cifra con la clave B y descifra con la A.
    Responder,
}

/// Estructura principal que mantiene el estado mutante de las claves.
///
/// Las claves internas se limpian con `zeroize` al mutar y al destruir la instancia.
/// Alerta pro al libreria, se esta viendo una optimizacion para este punto
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoNugget {
    pub(crate) tx_key: [u8; 32],
    pub(crate) rx_key: [u8; 32],
    pub(crate) tx_seq: u64,
    pub(crate) rx_seq: u64,
    pub(crate) epoch: u64,
    pub(crate) context: Vec<u8>,
    pub(crate) requires_resume_ack: bool,
}

impl std::fmt::Debug for CryptoNugget {
    /// Implementación segura: nunca expone material de clave.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoNugget")
            .field("tx_key", &"<redacted>")
            .field("rx_key", &"<redacted>")
            .field("tx_seq", &self.tx_seq)
            .field("rx_seq", &self.rx_seq)
            .field("epoch", &self.epoch)
            .field("requires_resume_ack", &self.requires_resume_ack)
            .finish()
    }
}

impl CryptoNugget {
    /// Crea un builder con el contexto por defecto.
    pub fn builder(seed: &MasterSeed, role: Role) -> crate::Builder<'_> {
        crate::Builder::new(seed, role, DEFAULT_CONTEXT)
    }

    /// Crea un builder con separación de dominio explícita.
    pub fn builder_with_context<'a>(
        seed: &'a MasterSeed,
        role: Role,
        context: &'a [u8],
    ) -> crate::Builder<'a> {
        crate::Builder::new(seed, role, context)
    }

    /// Inicializa un nuevo Nugget usando el contexto por defecto de la crate.
    pub fn new(seed: &MasterSeed, role: Role) -> Self {
        Self::new_with_context(seed, role, DEFAULT_CONTEXT)
    }

    /// Inicializa un nuevo Nugget con separación de dominio por aplicación/protocolo.
    ///
    /// El `context` debería ser estable y específico, por ejemplo:
    /// `b"mi-app/chat/v1"`. Dos proyectos distintos no deberían reutilizar el
    /// mismo contexto si comparten accidentalmente una semilla.
    pub fn new_with_context(seed: &MasterSeed, role: Role, context: &[u8]) -> Self {
        let mut salt = b"CryptoNugget:seed:v1".to_vec();
        salt.push(0);
        salt.extend_from_slice(context);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), seed.as_bytes());
        let mut clave_a = [0u8; 32];
        let mut clave_b = [0u8; 32];
        hkdf.expand(b"tx-key:a", &mut clave_a)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");
        hkdf.expand(b"tx-key:b", &mut clave_b)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");

        let (tx, rx) = match role {
            Role::Initiator => (clave_a, clave_b),
            Role::Responder => (clave_b, clave_a),
        };

        CryptoNugget {
            tx_key: tx,
            rx_key: rx,
            tx_seq: 0,
            rx_seq: 0,
            epoch: 0,
            context: context.to_vec(),
            requires_resume_ack: false,
        }
    }

    pub(crate) fn from_persisted_state(
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        tx_seq: u64,
        rx_seq: u64,
        epoch: u64,
        context: Vec<u8>,
    ) -> Self {
        Self {
            tx_key,
            rx_key,
            tx_seq,
            rx_seq,
            epoch,
            context,
            requires_resume_ack: true,
        }
    }

    /// Cifra el texto, devuelve el paquete v2 en Base64 y MUTA la clave inmediatamente.
    ///
    /// Wire v2: `version=2 ‖ flags=0 ‖ sequence(8 BE) ‖ nonce(12) ‖ ciphertext+tag`.
    pub fn cifrar(&mut self, texto_plano: &str) -> Result<String, Error> {
        self.cifrar_bytes(texto_plano.as_bytes())
    }

    /// Variante binaria de [`Self::cifrar`] para payloads que no son UTF-8.
    ///
    /// Mismo formato de paquete (v2 `flags=0`) y mismas garantías de
    /// autenticación, secuencia y ratcheting. Usalo cuando el plaintext sea
    /// binario (ej. estructuras serializadas, archivos cortos).
    pub fn cifrar_bytes(&mut self, plaintext: &[u8]) -> Result<String, Error> {
        let packet = self.cifrar_bytes_with_aad(plaintext, b"")?;
        Ok(packet.to_base64())
    }

    /// Cifra `plaintext` enlazando un AAD opcional al cifrado autenticado.
    ///
    /// El receptor debe llamar a [`Self::descifrar_bytes_with_aad`] con el mismo
    /// `user_aad` o el descifrado fallará con [`Error::Autenticacion`]. Pasar
    /// un `user_aad` vacío (`b""`) es byte-equivalente a [`Self::cifrar_bytes`]:
    /// el bit 0 de `flags` queda en 0 y la AAD interna no incluye prefijo
    /// de longitud.
    ///
    /// Devuelve el [`Packet`] tipado; serializalo con [`Packet::to_bytes`] o
    /// [`Packet::to_base64`] según el transporte.
    pub fn cifrar_bytes_with_aad(
        &mut self,
        plaintext: &[u8],
        user_aad: &[u8],
    ) -> Result<Packet, Error> {
        if self.requires_resume_ack {
            return Err(Error::EstadoSinReanudar);
        }
        let key = Key::<Aes256Gcm>::from_slice(&self.tx_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_ga = Aes256Gcm::generate_nonce(&mut OsRng);
        let sequence = self.tx_seq;

        let flags = if user_aad.is_empty() {
            0u8
        } else {
            FLAG_AAD_PRESENT
        };
        let internal_aad = build_internal_aad_v2_with_epoch(flags, sequence, user_aad, self.epoch);

        let ciphertext = cipher
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: plaintext,
                    aad: &internal_aad,
                },
            )
            .map_err(|_| Error::Cifrado)?;

        self.mutar_clave(true);
        self.tx_seq = self.tx_seq.checked_add(1).ok_or(Error::Cifrado)?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_ga.as_slice());

        Ok(Packet {
            version: WIRE_VERSION_V2,
            flags,
            sequence,
            nonce,
            ciphertext,
        })
    }

    /// Descifra el paquete, extrae el mensaje UTF-8 y MUTA la clave de recepción.
    ///
    /// Acepta wire v2 (formato actual) y wire v1 (legacy, compat 1 ciclo).
    /// Si el plaintext no es UTF-8 válido devuelve [`Error::Utf8`]. Para
    /// payloads binarios usá [`Self::descifrar_bytes`].
    ///
    /// **Importante:** un paquete autenticado y en secuencia siempre avanza el
    /// ratchet, incluso si el plaintext no es UTF-8. Esto evita inconsistencias
    /// de estado entre llamadas string y binarias.
    pub fn descifrar(&mut self, paquete_base64: &str) -> Result<String, Error> {
        let bytes = self.descifrar_bytes(paquete_base64)?;
        String::from_utf8(bytes).map_err(|_| Error::Utf8)
    }

    /// Variante binaria de [`Self::descifrar`] para payloads que no son UTF-8.
    ///
    /// Acepta tanto wire v2 (default) como wire v1 (legacy, OrderedChannel
    /// only). Internamente parsea el paquete con [`Packet::from_base64`] y
    /// despacha al camino v1 o v2 sin AAD adicional.
    pub fn descifrar_bytes(&mut self, paquete_base64: &str) -> Result<Vec<u8>, Error> {
        let packet = Packet::from_base64(paquete_base64)?;
        self.descifrar_bytes_with_aad(&packet, b"")
    }

    /// Descifra un [`Packet`] verificando el `user_aad` esperado.
    ///
    /// Para wire v2 reconstruye la AAD interna con
    /// `version‖flags‖seq‖[len‖user_aad if flags bit 0 set]` y la entrega a
    /// AES-GCM. Si el `user_aad` no coincide con el usado al cifrar, falla
    /// con [`Error::Autenticacion`] y NO avanza `rx_seq` ni rota la clave.
    ///
    /// Para wire v1 (legacy, `flags` siempre 0, `user_aad` debe ser vacío) usa
    /// la AAD histórica `version=1‖seq(8 BE)`.
    pub fn descifrar_bytes_with_aad(
        &mut self,
        packet: &Packet,
        user_aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let epoch_candidates: &[u64] = match packet.version {
            WIRE_VERSION_V2 if self.epoch == 0 => &[self.epoch, self.epoch + 1],
            WIRE_VERSION_V2 => &[self.epoch],
            WIRE_VERSION_V1 => {
                if !user_aad.is_empty() {
                    return Err(Error::Autenticacion);
                }
                &[self.epoch]
            }
            other => return Err(Error::VersionNoSoportada(other)),
        };

        let nonce = Nonce::from_slice(&packet.nonce);
        let key = Key::<Aes256Gcm>::from_slice(&self.rx_key);
        let cipher = Aes256Gcm::new(key);

        let mut authenticated_epoch = self.epoch;
        let plaintext = match packet.version {
            WIRE_VERSION_V2 => {
                let mut plaintext = None;
                for candidate in epoch_candidates {
                    let internal_aad = build_internal_aad_v2_with_epoch(
                        packet.flags,
                        packet.sequence,
                        user_aad,
                        *candidate,
                    );
                    if let Ok(opened) = cipher.decrypt(
                        nonce,
                        Payload {
                            msg: &packet.ciphertext,
                            aad: &internal_aad,
                        },
                    ) {
                        authenticated_epoch = *candidate;
                        plaintext = Some(opened);
                        break;
                    }
                }
                plaintext.ok_or(Error::Autenticacion)?
            }
            WIRE_VERSION_V1 => {
                let internal_aad = build_internal_aad_v1(packet.sequence);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &packet.ciphertext,
                            aad: &internal_aad,
                        },
                    )
                    .map_err(|_| Error::Autenticacion)?
            }
            other => return Err(Error::VersionNoSoportada(other)),
        };

        // Una vez autenticado: la secuencia y los flags fueron AAD, así que un
        // attacker no puede mover ninguno sin invalidar el tag. Avanzamos el
        // ratchet.
        self.mutar_clave(false);
        self.rx_seq = self.rx_seq.checked_add(1).ok_or(Error::Autenticacion)?;
        self.epoch = authenticated_epoch;

        Ok(plaintext)
    }

    fn mutar_clave(&mut self, es_tx: bool) {
        let clave_actual = if es_tx { &self.tx_key } else { &self.rx_key };

        let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:ratchet:v1"), clave_actual);
        let mut nueva_clave = [0u8; 32];
        hkdf.expand(b"ratchet-key:v1", &mut nueva_clave)
            .expect("HKDF expand nunca falla con SHA256 y 32 bytes");

        if es_tx {
            self.tx_key.zeroize();
            self.tx_key.copy_from_slice(&nueva_clave);
        } else {
            self.rx_key.zeroize();
            self.rx_key.copy_from_slice(&nueva_clave);
        }
        nueva_clave.zeroize();
    }

    /// Devuelve una huella de diagnóstico del estado actual del ratchet.
    ///
    /// La huella se deriva con HKDF-SHA-256 sobre las claves internas usando
    /// una etiqueta de dominio fija (`CryptoNugget:fingerprint:v1`). **No
    /// expone bytes crudos del material de clave** y no permite reconstruirlas:
    /// es una función de un solo sentido pensada para comparar estados o
    /// detectar desincronización en logs locales.
    ///
    /// El formato es estable dentro de la versión 0.x pero no es parte del
    /// contrato de wire format.
    pub fn obtener_estado_adn(&self) -> String {
        let tx_fp = fingerprint(&self.tx_key, b"fp:tx");
        let rx_fp = fingerprint(&self.rx_key, b"fp:rx");
        format!(
            "TX:{:02X}{:02X}{:02X}{:02X} RX:{:02X}{:02X}{:02X}{:02X} SEQ:{}/{}",
            tx_fp[0],
            tx_fp[1],
            tx_fp[2],
            tx_fp[3],
            rx_fp[0],
            rx_fp[1],
            rx_fp[2],
            rx_fp[3],
            self.tx_seq,
            self.rx_seq
        )
    }

    /// Compatibilidad semántica: genera una semilla maestra segura.
    pub fn generar_semilla_maestra() -> MasterSeed {
        MasterSeed::generate()
    }

    /// Empaqueta la semilla en un enlace de invitación.
    ///
    /// Advertencia: el enlace contiene el secreto raíz. Preferí un canal seguro y
    /// efímero. Esta función queda como conveniencia explícita, no como transporte
    /// seguro.
    pub fn generar_enlace_invitacion(seed: &MasterSeed) -> String {
        format!(
            "nugget://sincronizar?v=1&semilla={}",
            seed.export_for_transfer()
        )
    }

    /// Extrae la semilla de un enlace de invitación.
    pub fn extraer_semilla_de_enlace(enlace: &str) -> Result<MasterSeed, Error> {
        if let Some(semilla) = enlace.strip_prefix("nugget://sincronizar?v=1&semilla=") {
            MasterSeed::from_transfer_token(semilla).map_err(|_| Error::EnlaceInvalido)
        } else {
            Err(Error::EnlaceInvalido)
        }
    }
}

/// Deriva una huella corta y no reversible de una clave interna.
///
/// Usa HKDF-SHA-256 con la clave como IKM y una etiqueta `info` de dominio,
/// devolviendo 4 bytes. No filtra el material original.
fn fingerprint(key: &[u8; 32], info: &[u8]) -> [u8; 4] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"CryptoNugget:fingerprint:v1"), key);
    let mut out = [0u8; 4];
    hkdf.expand(info, &mut out)
        .expect("HKDF expand nunca falla con SHA256 y 4 bytes");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::V2_HEADER_LEN;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn actores() -> (CryptoNugget, CryptoNugget) {
        let semilla = CryptoNugget::generar_semilla_maestra();
        (
            CryptoNugget::new(&semilla, Role::Initiator),
            CryptoNugget::new(&semilla, Role::Responder),
        )
    }

    #[test]
    fn flujo_alice_bob_completo() {
        let (mut alice, mut bob) = actores();

        let msg1 = "¡Hola Bob!";
        let cifrado1 = alice.cifrar(msg1).unwrap();
        let descifrado1 = bob.descifrar(&cifrado1).unwrap();
        assert_eq!(descifrado1, msg1);

        let msg2 = "¿Cómo estás?";
        let cifrado2 = alice.cifrar(msg2).unwrap();
        let descifrado2 = bob.descifrar(&cifrado2).unwrap();
        assert_eq!(descifrado2, msg2);
    }

    #[test]
    fn clave_incorrecta_falla() {
        let semilla_a = CryptoNugget::generar_semilla_maestra();
        let semilla_b = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new(&semilla_a, Role::Initiator);
        let mut bob = CryptoNugget::new(&semilla_b, Role::Responder);

        let cifrado = alice.cifrar("secreto").unwrap();
        assert!(bob.descifrar(&cifrado).is_err());
    }

    #[test]
    fn paquete_corrupto_falla() {
        let (mut alice, mut bob) = actores();

        let cifrado = alice.cifrar("test").unwrap();
        let mut bytes = STANDARD.decode(&cifrado).unwrap();
        if bytes.len() > V2_HEADER_LEN + 1 {
            bytes[V2_HEADER_LEN + 1] ^= 0xFF;
        }
        let corrupto = STANDARD.encode(&bytes);

        assert!(matches!(
            bob.descifrar(&corrupto),
            Err(Error::Autenticacion)
        ));
    }

    #[test]
    fn metadata_autenticada_falla_si_se_modifica() {
        let (mut alice, mut bob) = actores();

        let cifrado = alice.cifrar("test").unwrap();
        let mut bytes = STANDARD.decode(&cifrado).unwrap();
        // byte 9 cae dentro del campo seq (offsets 2..10) en wire v2.
        bytes[9] ^= 0x01;
        let corrupto = STANDARD.encode(&bytes);

        assert!(matches!(
            bob.descifrar(&corrupto),
            Err(Error::Autenticacion)
        ));
    }

    #[test]
    fn paquete_demasiado_corto_falla() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut bob = CryptoNugget::new(&semilla, Role::Responder);
        let paquete_corto = STANDARD.encode(b"corto");
        assert!(matches!(
            bob.descifrar(&paquete_corto),
            Err(Error::PaqueteCorrupto)
        ));
    }

    #[test]
    fn cifrados_distintos_para_mismo_plaintext() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new(&semilla, Role::Initiator);

        let msg = "mismo texto";
        let c1 = alice.cifrar(msg).unwrap();
        let c2 = alice.cifrar(msg).unwrap();

        assert_ne!(c1, c2);
    }

    #[test]
    fn desincronizacion_por_orden_incorrecto() {
        let (mut alice, mut bob) = actores();

        let cifrado1 = alice.cifrar("primero").unwrap();
        let cifrado2 = alice.cifrar("segundo").unwrap();

        assert!(matches!(
            bob.descifrar(&cifrado2),
            Err(Error::Autenticacion)
        ));

        let descifrado1 = bob.descifrar(&cifrado1).unwrap();
        assert_eq!(descifrado1, "primero");
    }

    #[test]
    fn mensaje_repetido_falla() {
        let (mut alice, mut bob) = actores();

        let cifrado = alice.cifrar("no repetir").unwrap();
        let descifrado = bob.descifrar(&cifrado).unwrap();
        assert_eq!(descifrado, "no repetir");

        assert!(matches!(bob.descifrar(&cifrado), Err(Error::Autenticacion)));
    }

    #[test]
    fn enlace_invitacion_roundtrip() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let enlace = CryptoNugget::generar_enlace_invitacion(&semilla);
        let extraida = CryptoNugget::extraer_semilla_de_enlace(&enlace).unwrap();
        assert_eq!(
            extraida.export_for_transfer(),
            semilla.export_for_transfer()
        );
    }

    #[test]
    fn enlace_invalido_falla() {
        assert!(matches!(
            CryptoNugget::extraer_semilla_de_enlace("http://invalido"),
            Err(Error::EnlaceInvalido)
        ));
    }

    #[test]
    fn base64_invalido_falla() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut bob = CryptoNugget::new(&semilla, Role::Responder);
        assert!(matches!(
            bob.descifrar("!!!no-es-base64-valido!!!"),
            Err(Error::Base64(_))
        ));
    }

    #[test]
    fn contextos_distintos_no_interoperan() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new_with_context(&semilla, Role::Initiator, b"app-a/v1");
        let mut bob = CryptoNugget::new_with_context(&semilla, Role::Responder, b"app-b/v1");

        let cifrado = alice.cifrar("mensaje").unwrap();
        assert!(matches!(bob.descifrar(&cifrado), Err(Error::Autenticacion)));
    }

    #[test]
    fn ratcheting_sincronizacion_mantiene_estado() {
        let (mut alice, mut bob) = actores();

        let adn_inicial_alice = alice.obtener_estado_adn();
        let adn_inicial_bob = bob.obtener_estado_adn();

        let c = alice.cifrar("ratchet").unwrap();
        let _ = bob.descifrar(&c).unwrap();

        assert_ne!(alice.obtener_estado_adn(), adn_inicial_alice);
        assert_ne!(bob.obtener_estado_adn(), adn_inicial_bob);
        assert_eq!(alice.tx_key, bob.rx_key);
        assert_eq!(alice.rx_key, bob.tx_key);
        assert_eq!(alice.tx_seq, 1);
        assert_eq!(bob.rx_seq, 1);
    }

    #[test]
    fn semilla_cero_es_invalida() {
        assert!(matches!(
            MasterSeed::from_bytes([0u8; 32]),
            Err(Error::SemillaInvalida)
        ));
    }
}
