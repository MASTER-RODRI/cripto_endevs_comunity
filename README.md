# CryptoNugget

[![Crates.io](https://shields.io)](https://crates.io)
[![Documentation](https://docs.rs)](https://docs.rs)
[![License: MIT](https://shields.io)](https://opensource.org)

Un micro-módulo de cifrado excéntrico y seguro desarrollado en Rust. Utiliza **AES-GCM** para seguridad autenticada y un sistema de **Ratcheting** (trinquete) donde las claves mutan permanentemente después de cada uso. Nada se guarda, todo se transforma.

## 🛠️ Instalación

Añade `cripto_endevs_comunity` a las dependencias de tu archivo `Cargo.toml`:

```toml
[dependencies]
cripto_endevs_comunity = "0.1.4"
```

## 🚀 Ejemplo de Uso

Aquí tienes un ejemplo rápido de cómo inicializar el módulo y realizar un ciclo de cifrado con mutación de clave:

```rust
use cripto_endevs_comunity::{CryptoNugget, Role};

fn main() {
    println!("--- DEMOSTRACIÓN DEL CRYPTO NUGGET (RUST) ---\n");

    // Semilla maestra de 256 bits generada por el CSPRNG del sistema operativo.
    let semilla_secreta = CryptoNugget::generar_semilla_maestra();

    // Si necesitás transferirla, tratá este token como un secreto raíz.
    // No lo imprimas ni lo loguees en producción.
    let token_transferencia = semilla_secreta.export_for_transfer();
    let semilla_bob = cripto_endevs_comunity::MasterSeed::from_transfer_token(&token_transferencia)
        .expect("token de transferencia válido");

    // Iniciamos los nodos usando roles explícitos, no booleanos.
    let mut app_alice = CryptoNugget::new(&semilla_secreta, Role::Initiator);
    let mut app_bob = CryptoNugget::new(&semilla_bob, Role::Responder);

    println!("ADN Inicial Alice: {}", app_alice.obtener_estado_adn());
    println!("ADN Inicial Bob  : {}\n", app_bob.obtener_estado_adn());

    let mensaje1 = "¡Hola Bob, únete a la comunidad!";
    let cifrado1 = app_alice.cifrar(mensaje1).unwrap();
    println!("Alice envía: '{}'", mensaje1);
    println!("Cifrado (1): {}\n", cifrado1);

    let cifrado2 = app_alice.cifrar(mensaje1).unwrap();
    println!("Alice envía de nuevo el mismo texto...");
    println!("Cifrado (2): {}", cifrado2);
    println!("(Distinto por nonce aleatorio, secuencia autenticada y ratcheting)\n");

    match app_bob.descifrar(&cifrado1) {
        Ok(msg) => println!("Bob recibe y lee (1): {}", msg),
        Err(e) => println!("Error Bob 1: {}", e),
    }

    match app_bob.descifrar(&cifrado2) {
        Ok(msg) => println!("Bob recibe y lee (2): {}\n", msg),
        Err(e) => println!("Error Bob 2: {}", e),
    }

    println!("ADN Final Alice: {}", app_alice.obtener_estado_adn());
    println!("ADN Final Bob  : {}", app_bob.obtener_estado_adn());
    println!("\nOperación completada.");
}

```


## 🔒 Mecánica de Seguridad

* **AES-256-GCM:** Cifrado simétrico autenticado para garantizar confidencialidad e integridad.
* **HKDF-SHA256:** KDF estándar para derivar las claves iniciales y para el ratcheting tras cada operación.
* **MasterSeed:** Tipo dedicado para encapsular semillas de 256 bits y evitar el uso normal de contraseñas humanas o strings arbitrarios.
* **Roles explícitos:** `Role::Initiator` y `Role::Responder` reemplazan el antiguo booleano `true/false`.
* **Contexto de aplicación:** `new_with_context` permite separar dominios entre proyectos, por ejemplo `b"mi-app/chat/v1"`.
* **Formato versionado:** El paquete incluye `version || sequence || nonce || ciphertext+tag`, con `version` y `sequence` autenticados como AAD.
* **Zeroize:** Las claves internas se limpian de memoria de forma segura al mutar y al destruir la instancia.

## Alcance recomendado

CryptoNugget es una primitiva de cifrado simétrico autenticado con ratcheting para canales ordenados entre dos partes que ya comparten una semilla de alta entropía. No implementa intercambio de claves, autenticación de identidad, manejo de grupos, transporte seguro, persistencia segura, multi-dispositivo ni soporte nativo para mensajes fuera de orden.

## 🧪 Tests y Validación

La librería incluye una suite completa de pruebas unitarias para garantizar su fiabilidad en producción. Puedes ejecutar las pruebas en tu entorno local con:
```rust
    cargo test
```
La suite valida:

1. Flujo completo: Alice cifra, Bob descifra exitosamente.
2. Resistencia a ataques Replay/Estáticos: El mismo texto siempre genera criptogramas distintos.
3. Autenticación Estricta: Rechazo de descifrados con claves incorrectas o desincronizadas.
4. Protección contra Corrupción: Rechazo seguro (sin panic) de paquetes cortos, corruptos o con Base64 inválido.
5. Estrés de Ratcheting: Validación de que los nodos se mantienen sincronizados tras mutar cientos de veces consecutivas.

## ✒️ Autor

* **Desarrollador:** ENRODMONTPAR
* **GitHub C#:** [@MASTER-RODRI](https://github.com/MASTER-RODRI/cripto_endevs_comunity_C-)
* **GitHub RUST:** [@MASTER-RODRI](https://github.com/MASTER-RODRI/cripto_endevs_comunity)
* **Crates.io:** [@MASTER-RODRI](https://crates.io/crates/cripto_endevs_comunity)
* **nugget.org:** [@ENRODMONTPAR](https://www.nuget.org/packages/cripto_endevs_comunity)
* **npmjs.com:** [@ENRODMONTPAR](https://www.npmjs.com/package/cripto_endevs_comunity)

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
