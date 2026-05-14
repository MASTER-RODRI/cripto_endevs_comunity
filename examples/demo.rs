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
