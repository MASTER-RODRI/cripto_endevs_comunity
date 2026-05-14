//! Errores tipados de la crate.
//!
//! Este módulo aísla el enum `Error` para que los módulos de modos, paquete y
//! persistencia puedan compartirlo sin acoplarse a `lib.rs`. Todos los nombres
//! son en español por convención del API público (ver `Cargo.toml`).

/// Errores propios del módulo de cifrado.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Error al decodificar Base64.
    Base64(String),
    /// Paquete corrupto, demasiado corto o con formato inválido.
    PaqueteCorrupto,
    /// Versión de paquete no soportada.
    VersionNoSoportada(u8),
    /// Fallo de autenticación (clave incorrecta, desincronización o manipulación).
    Autenticacion,
    /// El texto descifrado no es UTF-8 válido.
    Utf8,
    /// Error interno durante el cifrado.
    Cifrado,
    /// La semilla no tiene el formato mínimo esperado.
    SemillaInvalida,
    /// Formato de enlace de invitación inválido.
    EnlaceInvalido,
    /// La configuración del modo solicitado es inválida.
    ModoInvalido,
    /// Paquete repetido dentro de una ventana anti-replay.
    Repetido,
    /// Paquete fuera de la ventana aceptada.
    FueraDeOrden,
    /// Estado importado pendiente de confirmación explícita del operador.
    EstadoSinReanudar,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64(e) => write!(f, "Error decodificando Base64: {}", e),
            Error::PaqueteCorrupto => write!(f, "Paquete corrupto o demasiado corto"),
            Error::VersionNoSoportada(version) => {
                write!(f, "Versión de paquete no soportada: {}", version)
            }
            Error::Autenticacion => write!(
                f,
                "Error de autenticación, clave incorrecta o paquete manipulado"
            ),
            Error::Utf8 => write!(f, "El texto descifrado no es UTF-8 válido"),
            Error::Cifrado => write!(f, "Error crítico en el cifrado"),
            Error::SemillaInvalida => write!(f, "La semilla debe contener 32 bytes no nulos"),
            Error::EnlaceInvalido => write!(f, "Formato de enlace Nugget inválido o corrupto"),
            Error::ModoInvalido => write!(f, "Modo de operación inválido"),
            Error::Repetido => write!(f, "Paquete repetido"),
            Error::FueraDeOrden => write!(f, "Paquete fuera de la ventana aceptada"),
            Error::EstadoSinReanudar => write!(
                f,
                "Estado importado sin confirmación explícita de reanudación"
            ),
        }
    }
}

impl std::error::Error for Error {}
