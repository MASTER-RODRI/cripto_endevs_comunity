use cripto_endevs_comunity::{
    ChronoMeshNode, ChronoWalJournal, CryptoNugget, DualSlotContainer, MasterSeed, Role,
};

fn main() {
    println!("=== 1. PRUEBA DE SUPERVIVENCIA A APAGÓN EN GUARDADO DE ESTADO (DUAL-SLOT A/B) ===\n");

    let seed = MasterSeed::generate();
    let context = b"ia-core:distributed-memory:v5";
    let wrap_key = seed.derive_wrap_key(context);

    let node_back = ChronoMeshNode::new(&seed, context, 10, 1, 30_000);
    let mut dual_slot = DualSlotContainer::new();

    // Emitimos 2 paquetes y guardamos la Generación 1 en Slot A
    let now_ms = 1_760_443_800_000;
    let p1 = node_back.seal_realtime(b"Estado memoria IA #1", b"aad:1", now_ms).unwrap();
    let p2 = node_back.seal_realtime(b"Estado memoria IA #2", b"aad:2", now_ms + 5).unwrap();

    let cp1 = node_back.export_checkpoint(&wrap_key).unwrap();
    let gen1 = dual_slot.commit_state(&cp1, &wrap_key).unwrap();
    println!("Snapshot Generación {} sellado en Slot A.", gen1);
// 1. Imprimir los paquetes completos en Base64 (Wire v3) y el Ciphertext puro en Hex
    println!("Cifrado p1 (Wire v3 Base64): {}", p1.to_base64());
    println!("Cifrado p2 (Wire v3 Base64): {}", p2.to_base64());

    println!("p1 Nonce + Ciphertext (Hex): {:02X?} | {:02X?}", p1.nonce, p1.ciphertext);
    println!("p2 Nonce + Ciphertext (Hex): {:02X?} | {:02X?}\n", p2.nonce, p2.ciphertext);

    // 2. Prueba de Excentricidad / Efecto Avalancha (mismo texto plano, mismo milisegundo)
    let muestra_a = node_back.seal_realtime(b"Mismo contexto IA", b"aad", now_ms).unwrap();
    let muestra_b = node_back.seal_realtime(b"Mismo contexto IA", b"aad", now_ms).unwrap();
    let bits_distintos: u32 = muestra_a.ciphertext.iter()
        .zip(muestra_b.ciphertext.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    let total_bits = (muestra_a.ciphertext.len() * 8) as f64;
    println!("Muestra A (Base64): {}", muestra_a.to_base64());
    println!("Muestra B (Base64): {}", muestra_b.to_base64());
    println!(
        "Excentricidad (Distancia de Hamming en Ciphertext): {}/{} bits ({:.2}% - ideal ~50.0%)\n",
        bits_distintos, total_bits as u32, (bits_distintos as f64 / total_bits) * 100.0
    );
    // Emitimos un 3er paquete y guardamos la Generación 2 en Slot B
    let p3 = node_back.seal_realtime(b"Estado memoria IA #3", b"aad:3", now_ms + 10).unwrap();
    let cp2 = node_back.export_checkpoint(&wrap_key).unwrap();
    let gen2 = dual_slot.commit_state(&cp2, &wrap_key).unwrap();
    println!("Snapshot Generación {} sellado en Slot B.", gen2);

    // SIMULACIÓN DE CORTE ELÉCTRICO A MITAD DE ESCRITURA DEL SLOT B EN DISCO:
    // Corrompemos los últimos 10 bytes del archivo serializado (donde vive el Slot B)
    let mut disk_bytes = dual_slot.to_bytes().unwrap();
    let truncated_len = disk_bytes.len() - 10;
    disk_bytes.truncate(truncated_len);

    // Al reiniciar el servidor tras el apagón, DualSlotContainer detecta que Slot B quedó truncado
    // y hace fallback automático al Slot A (Generación 1) sin perder el estado ni corromperse:
    let recovered_container = DualSlotContainer::from_bytes(&disk_bytes).unwrap();
    let (rec_gen, rec_cp) = recovered_container.recover_latest_valid(&wrap_key).unwrap();
    println!(
        "Auto-recuperación tras apagón exitosa -> Rescatada Generación {} íntegra.\n",
        rec_gen
    );
    assert_eq!(rec_gen, gen1);

    let rebooted_node = ChronoMeshNode::new(&seed, context, 10, 1, 30_000);
    rebooted_node.restore_checkpoint(&rec_cp, &wrap_key).unwrap();
    println!(
        "Nodo restaurado en nueva época anti-colisión: epoch={}, tx_seq={}\n",
        rebooted_node.current_epoch(),
        rebooted_node.current_tx_seq()
    );

    println!("=== 2. BITÁCORA WAL ENCADENADA POR SHA-256 CON CORTE ELÉCTRICO AL FINAL ===\n");

    let mut wal = ChronoWalJournal::new();
    let mut wal_file_on_disk = Vec::new();

    wal_file_on_disk.extend_from_slice(&wal.encode_append_frame(&p1).unwrap());
    wal_file_on_disk.extend_from_slice(&wal.encode_append_frame(&p2).unwrap());
    let frame3 = wal.encode_append_frame(&p3).unwrap();

    // Simulamos que el servidor muere cuando solo había escrito la mitad del frame 3 en disco:
    wal_file_on_disk.extend_from_slice(&frame3[..frame3.len() / 2]);

    // Al volver la energía, `recover_from_bytes` verifica toda la cadena SHA-256, rescata p1 y p2
    // y nos indica exactamente dónde truncar la cola huérfana del apagón:
    let report = ChronoWalJournal::recover_from_bytes(&wal_file_on_disk).unwrap();
    assert_eq!(report.packets.len(), 2);
    assert!(report.had_truncated_tail);

    let plaintexts = ChronoWalJournal::decrypt_recovered_wal(&rebooted_node, &report, b"aad:1")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    println!(
        "Bitácora WAL recuperada: {} paquetes íntegros verificados por cadena SHA-256, cola truncada detectada={}",
        report.packets.len(),
        report.had_truncated_tail
    );
    let _ = (CryptoNugget::generar_semilla_maestra(), Role::Initiator, plaintexts);
}
