//! Errores tipados de la crate (v0.5 - Multi-Language FFI & Self-Healing Persistence).
//!
//! Incluye códigos de retorno C-ABI deterministas (`to_ffi_code` / `from_ffi_code`)
//! para integración directa con C#, C/C++, Java, TypeScript/Node y Python.

/// Errores propios del módulo de cifrado y persistencia resiliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Error al decodificar Base64.
    Base64(String),
    /// Paquete o bloque persistido corrupto, truncado o con formato inválido.
    PaqueteCorrupto,
    /// Versión de paquete o snapshot no soportada.
    VersionNoSoportada(u8),
    /// Fallo de autenticación AEAD (clave incorrecta, desincronización o manipulación).
    Autenticacion,
    /// El texto descifrado no es UTF-8 válido.
    Utf8,
    /// Error interno o desbordamiento de secuencia/epoch durante el cifrado.
    Cifrado,
    /// La semilla no tiene la entropía mínima esperada (ej. 32 bytes nulos o repetidos).
    SemillaInvalida,
    /// Formato de enlace de invitación inválido.
    EnlaceInvalido,
    /// La configuración del modo solicitado es inválida.
    ModoInvalido,
    /// Paquete repetido dentro de la ventana o bitmap anti-replay.
    Repetido,
    /// Paquete fuera de la ventana aceptada (demasiado antiguo o salto excesivo).
    FueraDeOrden,
    /// Estado importado pendiente de confirmación explícita del operador (`mark_resumed`).
    EstadoSinReanudar,
    /// El paquete excede la ventana de validez temporal (TTL / Clock Skew).
    TiempoExpiradoOInvalido,
    /// El tamaño del AAD o payload supera el límite representable de 32 bits (CWE-190).
    AadDemasiadoLargo,
    /// El hash acumulativo de integridad (SHA-256) o cadena WAL no coincide con el estado esperado.
    IntegridadContextoCorrupta,
    /// Error de puntero nulo, buffer insuficiente o pánico capturado en la frontera FFI.
    FfiParametroInvalido,
    /// Error de entrada/salida (I/O) en disco o almacenamiento persistente.
    Io(String),
}

impl Error {
    /// Convierte el error a un código entero negativo estable para C-ABI (C#, Java, C, TS).
    /// `0` o positivo representa éxito en las funciones FFI.
    pub const fn to_ffi_code(&self) -> i32 {
        match self {
            Error::Base64(_) => -1,
            Error::PaqueteCorrupto => -2,
            Error::VersionNoSoportada(_) => -3,
            Error::Autenticacion => -4,
            Error::Utf8 => -5,
            Error::Cifrado => -6,
            Error::SemillaInvalida => -7,
            Error::EnlaceInvalido => -8,
            Error::ModoInvalido => -9,
            Error::Repetido => -10,
            Error::FueraDeOrden => -11,
            Error::EstadoSinReanudar => -12,
            Error::TiempoExpiradoOInvalido => -13,
            Error::AadDemasiadoLargo => -14,
            Error::IntegridadContextoCorrupta => -15,
            Error::FfiParametroInvalido => -16,
            Error::Io(_) => -17,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64(e) => write!(f, "Error decodificando Base64: {}", e),
            Error::PaqueteCorrupto => write!(f, "Paquete o registro corrupto o demasiado corto"),
            Error::VersionNoSoportada(version) => {
                write!(f, "Versión de formato no soportada: {}", version)
            }
            Error::Autenticacion => write!(
                f,
                "Error de autenticación AEAD, clave incorrecta o paquete manipulado"
            ),
            Error::Utf8 => write!(f, "El texto descifrado no es UTF-8 válido"),
            Error::Cifrado => {
                write!(
                    f,
                    "Error crítico en el cifrado o límite de secuencia alcanzado"
                )
            }
            Error::SemillaInvalida => {
                write!(f, "La semilla debe contener 32 bytes de alta entropía")
            }
            Error::EnlaceInvalido => write!(f, "Formato de enlace Nugget inválido o corrupto"),
            Error::ModoInvalido => write!(f, "Modo de operación inválido"),
            Error::Repetido => write!(f, "Paquete repetido (Replay detectado)"),
            Error::FueraDeOrden => write!(f, "Paquete fuera de la ventana aceptada"),
            Error::EstadoSinReanudar => write!(
                f,
                "Estado importado sin confirmación explícita de reanudación"
            ),
            Error::TiempoExpiradoOInvalido => write!(
                f,
                "El paquete está fuera de la ventana de tiempo permitida (TTL/Skew)"
            ),
            Error::AadDemasiadoLargo => write!(
                f,
                "Los metadatos AAD o bloque superan el límite máximo permitido"
            ),
            Error::IntegridadContextoCorrupta => write!(
                f,
                "Fallo en el SHA-256 de integración: se detectaron paquetes perdidos o corrupción de cadena"
            ),
            Error::FfiParametroInvalido => write!(
                f,
                "Parámetro FFI inválido (puntero nulo o capacidad de buffer insuficiente)"
            ),
            Error::Io(e) => write!(f, "Error de entrada/salida (I/O) en almacenamiento: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}
