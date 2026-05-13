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

type HmacSha256 = Hmac<Sha256>;

/// Estructura principal que mantiene el estado mutante de las claves.
pub struct CryptoNugget {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
}

impl CryptoNugget {
    /// Inicializa un nuevo Nugget. Las dos apps deben usar la misma semilla.
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
    pub fn cifrar(&mut self, texto_plano: &str) -> String {
        let key = Key::<Aes256Gcm>::from_slice(&self.tx_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 

        let ciphertext = cipher
            .encrypt(&nonce, texto_plano.as_bytes())
            .expect("Error crítico en el cifrado");

        self.mutar_clave(true);

        let mut paquete = nonce.to_vec();
        paquete.extend_from_slice(&ciphertext);
        STANDARD.encode(paquete)
    }

    /// Descifra el paquete, extrae el mensaje y MUTA la clave de recepción.
    pub fn descifrar(&mut self, paquete_base64: &str) -> Result<String, &'static str> {
        let empaquetado = STANDARD
            .decode(paquete_base64)
            .map_err(|_| "Error decodificando Base64")?;

        if empaquetado.len() < 12 + 16 {
            return Err("Paquete corrupto o demasiado corto");
        }

        let (nonce_bytes, ciphertext) = empaquetado.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&self.rx_key);
        let cipher = Aes256Gcm::new(key);

        let texto_plano = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Error de autenticación o clave incorrecta (Desincronizado)")?;

        self.mutar_clave(false);

        String::from_utf8(texto_plano).map_err(|_| "El texto descifrado no es UTF-8 válido")
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

    /// Muestra un fragmento del ADN actual para verificar la mutación.
    pub fn obtener_estado_adn(&self) -> String {
        format!(
            "TX:{:02X}{:02X}{:02X}{:02X}... RX:{:02X}{:02X}{:02X}{:02X}...",
            self.tx_key[0], self.tx_key[1], self.tx_key[2], self.tx_key[3],
            self.rx_key[0], self.rx_key[1], self.rx_key[2], self.rx_key[3]
        )
    }

    /// Genera una semilla maestra de 256 bits de entropía pura (Quantum-Safe)
    pub fn generar_semilla_maestra() -> String {
        let mut llave_cruda = [0u8; 32];
        OsRng.fill_bytes(&mut llave_cruda); 
        STANDARD.encode(llave_cruda)
    }

    /// Empaqueta la semilla en un enlace (URI) excéntrico para compartir
    pub fn generar_enlace_invitacion(semilla: &str) -> String {
        format!("nugget://sincronizar?semilla={}", semilla)
    }

    /// Extrae la semilla de un enlace de invitación
    pub fn extraer_semilla_de_enlace(enlace: &str) -> Result<String, &'static str> {
        if let Some(semilla) = enlace.strip_prefix("nugget://sincronizar?semilla=") {
            Ok(semilla.to_string())
        } else {
            Err("Formato de enlace Nugget inválido o corrupto")
        }
    }
}