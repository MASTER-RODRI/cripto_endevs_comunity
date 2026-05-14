//! # CryptoNugget
//! 
//! Desarrollado por: ENRODMONTPAR (https://github.com/MASTER-RODRI)
//! Licencia: MIT
//! 
//! Demo en línea: https://master-rodri.github.io/CryptoNuggetChat/
//! 
//! Un micro-módulo de cifrado excéntrico y seguro.
//! Utiliza AES-GCM para seguridad autenticada y un sistema de "Ratcheting" (trinquete)
//! donde las claves mutan permanentemente después de cada uso. Nada se guarda, todo se transforma.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Tipos de errores personalizados para el Nugget
#[derive(Debug, PartialEq)]
pub enum NuggetError {
    CifradoFallido,
    PaqueteCorruptoODemasiadoCorto,
    ErrorDecodificacionBase64,
    AutenticacionDesincronizada,
    EnlaceInvalido,
    ErrorUtf8,
}

impl fmt::Display for NuggetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NuggetError::CifradoFallido => write!(f, "Fallo crítico al intentar cifrar el mensaje."),
            NuggetError::PaqueteCorruptoODemasiadoCorto => write!(f, "El paquete es demasiado corto o está corrupto."),
            NuggetError::ErrorDecodificacionBase64 => write!(f, "El paquete no es un Base64 válido."),
            NuggetError::AutenticacionDesincronizada => write!(f, "Fallo de autenticación: Clave incorrecta o los nodos están desincronizados."),
            NuggetError::EnlaceInvalido => write!(f, "El enlace de invitación tiene un formato inválido."),
            NuggetError::ErrorUtf8 => write!(f, "El texto descifrado no contiene formato UTF-8 válido."),
        }
    }
}

impl std::error::Error for NuggetError {}

/// Estructura principal que mantiene el estado de las claves.
/// Implementa ZeroizeOnDrop para garantizar el borrado seguro de la memoria
/// (sobreescritura con ceros) una vez que la estructura es destruida.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoNugget {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
}

impl CryptoNugget {
    /// Inicializa un nuevo Nugget a partir de una semilla compartida.
    pub fn new(semilla_inicial: &str, es_iniciador: bool) -> Self {
        let mut hasher_a = Sha256::new();
        hasher_a.update(semilla_inicial.as_bytes());
        hasher_a.update(b"NUGGET_TX");
        let clave_a: [u8; 32] = hasher_a.finalize().into();

        let mut hasher_b = Sha256::new();
        hasher_b.update(semilla_inicial.as_bytes());
        hasher_b.update(b"NUGGET_RX");
        let clave_b: [u8; 32] = hasher_b.finalize().into();

        let (tx, rx) = if es_iniciador {
            (clave_a, clave_b)
        } else {
            (clave_b, clave_a)
        };

        CryptoNugget {
            tx_key: tx,
            rx_key: rx,
        }
    }

    /// Cifra el texto, devuelve el paquete en Base64 y MUTA la clave inmediatamente.
    pub fn cifrar(&mut self, texto_plano: &str) -> Result<String, NuggetError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.tx_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 

        let ciphertext = cipher
            .encrypt(&nonce, texto_plano.as_bytes())
            .map_err(|_| NuggetError::CifradoFallido)?;

        self.mutar_clave(true);

        let mut paquete = nonce.to_vec();
        paquete.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(paquete))
    }

    /// Descifra el paquete, extrae el mensaje y MUTA la clave de recepción.
    pub fn descifrar(&mut self, paquete_base64: &str) -> Result<String, NuggetError> {
        let empaquetado = STANDARD
            .decode(paquete_base64)
            .map_err(|_| NuggetError::ErrorDecodificacionBase64)?;

        // 12 bytes nonce + 16 bytes auth tag = 28 bytes mínimo
        if empaquetado.len() < 28 {
            return Err(NuggetError::PaqueteCorruptoODemasiadoCorto);
        }

        let (nonce_bytes, ciphertext) = empaquetado.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&self.rx_key);
        let cipher = Aes256Gcm::new(key);

        let texto_plano = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| NuggetError::AutenticacionDesincronizada)?;

        self.mutar_clave(false);

        String::from_utf8(texto_plano).map_err(|_| NuggetError::ErrorUtf8)
    }

    fn mutar_clave(&mut self, es_tx: bool) {
        let clave_actual = if es_tx { &self.tx_key } else { &self.rx_key };

        let mut mac = <HmacSha256 as Mac>::new_from_slice(clave_actual)
            .expect("HMAC puede tomar claves");
        mac.update(b"EVOLUCION_NUGGET");
        
        let resultado = mac.finalize().into_bytes();

        if es_tx {
            self.tx_key.copy_from_slice(&resultado);
        } else {
            self.rx_key.copy_from_slice(&resultado);
        }
    }

    pub fn obtener_estado_adn(&self) -> String {
        format!(
            "TX:{:02X}{:02X}{:02X}{:02X}... RX:{:02X}{:02X}{:02X}{:02X}...",
            self.tx_key[0], self.tx_key[1], self.tx_key[2], self.tx_key[3],
            self.rx_key[0], self.rx_key[1], self.rx_key[2], self.rx_key[3]
        )
    }

    pub fn generar_semilla_maestra() -> String {
        let mut llave_cruda = [0u8; 32];
        OsRng.fill_bytes(&mut llave_cruda); 
        STANDARD.encode(llave_cruda)
    }

    pub fn generar_enlace_invitacion(semilla: &str) -> String {
        format!("nugget://sincronizar?semilla={}", semilla)
    }

    pub fn extraer_semilla_de_enlace(enlace: &str) -> Result<String, NuggetError> {
        if let Some(semilla) = enlace.strip_prefix("nugget://sincronizar?semilla=") {
            Ok(semilla.to_string())
        } else {
            Err(NuggetError::EnlaceInvalido)
        }
    }
}
// ==========================================
// MÓDULO DE TESTS
// ==========================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alice_cifra_bob_descifra() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new(&semilla, true);
        let mut bob = CryptoNugget::new(&semilla, false);

        let mensaje_original = "Mensaje súper secreto de prueba";
        let paquete_cifrado = alice.cifrar(mensaje_original).unwrap();
        
        let mensaje_descifrado = bob.descifrar(&paquete_cifrado).unwrap();
        assert_eq!(mensaje_original, mensaje_descifrado);
    }

    #[test]
    fn test_mismo_texto_genera_cifrados_distintos() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new(&semilla, true);

        let mensaje = "Hola";
        let cifrado1 = alice.cifrar(mensaje).unwrap();
        let cifrado2 = alice.cifrar(mensaje).unwrap();

        // El cifrado debe ser distinto debido al nonce y a la mutación de la clave
        assert_ne!(cifrado1, cifrado2);
    }

    #[test]
    fn test_falla_con_clave_incorrecta_o_desincronizada() {
        let semilla_alice = CryptoNugget::generar_semilla_maestra();
        let semilla_bob = CryptoNugget::generar_semilla_maestra(); // Semilla distinta

        let mut alice = CryptoNugget::new(&semilla_alice, true);
        let mut bob_impostor = CryptoNugget::new(&semilla_bob, false);

        let cifrado = alice.cifrar("Hola").unwrap();
        
        let resultado = bob_impostor.descifrar(&cifrado);
        assert_eq!(resultado, Err(NuggetError::AutenticacionDesincronizada));
    }

    #[test]
    fn test_paquetes_corruptos_fallan() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut bob = CryptoNugget::new(&semilla, false);

        // Intento 1: Base64 inválido
        let res_base64 = bob.descifrar("esto-no-es-base64!!!");
        assert_eq!(res_base64, Err(NuggetError::ErrorDecodificacionBase64));

        // Intento 2: Muy corto (menor a 28 bytes)
        let muy_corto = STANDARD.encode(vec![0u8; 10]);
        let res_corto = bob.descifrar(&muy_corto);
        assert_eq!(res_corto, Err(NuggetError::PaqueteCorruptoODemasiadoCorto));

        // Intento 3: Tamaño correcto pero datos basura (debe fallar autenticación GCM)
        let basura = STANDARD.encode(vec![0u8; 32]);
        let res_auth = bob.descifrar(&basura);
        assert_eq!(res_auth, Err(NuggetError::AutenticacionDesincronizada));
    }

    #[test]
    fn test_ratcheting_no_se_desincroniza() {
        let semilla = CryptoNugget::generar_semilla_maestra();
        let mut alice = CryptoNugget::new(&semilla, true);
        let mut bob = CryptoNugget::new(&semilla, false);

        // Envíanos 100 mensajes seguidos para probar que las claves mutan juntas sin romperse
        for i in 0..100 {
            let mensaje = format!("Mensaje número {}", i);
            let cifrado = alice.cifrar(&mensaje).unwrap();
            let descifrado = bob.descifrar(&cifrado).unwrap();
            assert_eq!(mensaje, descifrado);
        }
    }
}