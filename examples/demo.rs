use cripto_endevs_comunity::CryptoNugget;

fn main() {
    println!("--- DEMOSTRACIÓN DEL CRYPTO NUGGET (RUST) ---\n");

    // ALICE CREA LA CONEXIÓN
    let semilla_secreta = CryptoNugget::generar_semilla_maestra();
    let enlace_invitacion = CryptoNugget::generar_enlace_invitacion(&semilla_secreta);
    
    println!("=== RITUAL DE INICIALIZACIÓN ===");
    println!("Alice, envíale este enlace a Bob (O muéstralo como Código QR):");
    println!("{}\n==========================================\n", enlace_invitacion);

    // Iniciamos el nodo de Alice
    let mut app_alice = CryptoNugget::new(&semilla_secreta, true);

    // BOB RECIBE EL ENLACE Y SE CONECTA
    // Ahora extraer_semilla devuelve un Result, usamos expect() en la demo para manejar errores rápidamente
    let semilla_extraida = CryptoNugget::extraer_semilla_de_enlace(&enlace_invitacion)
        .expect("Bob falló al leer el enlace de invitación");
    
    // Iniciamos el nodo de Bob con la semilla que extrajo del enlace
    let mut app_bob = CryptoNugget::new(&semilla_extraida, false);

    println!("ADN Inicial Alice: {}", app_alice.obtener_estado_adn());
    println!("ADN Inicial Bob  : {}\n", app_bob.obtener_estado_adn());

    // 1. Mensaje 1
    let mensaje1 = "¡Hola Bob, únete a la comunidad!";
    // Ahora cifrar() devuelve Result, así que lo manejamos con expect() (o con match)
    let cifrado1 = app_alice.cifrar(mensaje1).expect("Error crítico al cifrar");
    
    println!("Alice envía: '{}'", mensaje1);
    println!("Cifrado (1): {}\n", cifrado1);

    // 2. Mismo mensaje, nuevo criptograma (y mutación)
    let cifrado2 = app_alice.cifrar(mensaje1).expect("Error crítico al cifrar");
    println!("Alice envía de nuevo el mismo texto...");
    println!("Cifrado (2): {}", cifrado2);
    println!("(Totalmente distinto debido al Nonce aleatorio y mutación)\n");

    // 3. Bob recibe y descifra
    // Usamos pattern matching (match) para manejar elegantemente el posible error
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
    println!("\nOperación completada. Al cerrarse el programa, 'zeroize' destruirá las claves en la RAM.");
}