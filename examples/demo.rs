use cripto_endevs_comunity::CryptoNugget;
fn main() {
    println!("--- DEMOSTRACIÓN DEL CRYPTO NUGGET (RUST) ---\n");

    // REEMPLAZAMOS LA CONTRASEÑA HUMANA POR ENTROPÍA PURA DE 256 BITS
    let semilla_secreta = CryptoNugget::generar_semilla_maestra();
    
    println!("=== ATENCIÓN: SEMILLA DE ALTA ENTROPÍA ===");
    println!("Guarda esto. Es imposible de memorizar o adivinar:");
    println!("{}\n==========================================\n", semilla_secreta);

    // Iniciamos los nodos usando la semilla de alta entropía
    let mut app_alice = CryptoNugget::new(&semilla_secreta, true);
    let mut app_bob = CryptoNugget::new(&semilla_secreta, false);

    println!("ADN Inicial Alice: {}", app_alice.obtener_estado_adn());
    println!("ADN Inicial Bob  : {}\n", app_bob.obtener_estado_adn());

    // 1. Mensaje 1
    let mensaje1 = "¡Hola Bob, únete a la comunidad!";
    let cifrado1 = app_alice.cifrar(mensaje1);
    println!("Alice envía: '{}'", mensaje1);
    println!("Cifrado (1): {}\n", cifrado1);

    // 2. Mismo mensaje, nuevo criptograma (y mutación)
    let cifrado2 = app_alice.cifrar(mensaje1);
    println!("Alice envía de nuevo el mismo texto...");
    println!("Cifrado (2): {}", cifrado2);
    println!("(Totalmente distinto debido al Nonce aleatorio y mutación)\n");

    // 3. Bob recibe y descifra
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
    println!("\nOperación completada con máxima eficiencia de memoria.");
}