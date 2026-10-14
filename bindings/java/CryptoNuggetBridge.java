package com.endevs.cryptonugget;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * CryptoNugget v0.5 - Conector para Java (JNI / JNA / Project Panama FFM) y Android (Kotlin/Java).
 *
 * Garantiza que el formato binario Wire v3 (Big-Endian) y los códigos de error de `src/ffi.rs`
 * sean 100 % compatibles entre Android/JVM, C# (.NET) y Rust.
 */
public final class CryptoNuggetBridge {

    public static final int V3_HEADER_LEN = 42;
    public static final int TAG_LEN = 16;

    public static final int CN_OK = 0;
    public static final int CN_ERR_CORRUPT_PACKET = -2;
    public static final int CN_ERR_AUTH_FAILED = -4;
    public static final int CN_ERR_REPLAY_DETECTED = -10;
    public static final int CN_ERR_TIME_EXPIRED = -13;
    public static final int CN_ERR_INTEGRITY_CORRUPTED = -15;

    /**
     * Metadatos extraídos de la cabecera Wire v3 sin necesidad de descifrar el paquete.
     * Útil para enrutadores, colas MQTT o inspectores de almacenamiento en Android/Backend.
     */
    public static final class PacketV3Metadata {
        public final byte version;
        public final byte flags;
        public final int nodeId;
        public final long epoch;
        public final long sequence;
        public final long timestampMs;

        public PacketV3Metadata(byte version, byte flags, int nodeId, long epoch, long sequence, long timestampMs) {
            this.version = version;
            this.flags = flags;
            this.nodeId = nodeId;
            this.epoch = epoch;
            this.sequence = sequence;
            this.timestampMs = timestampMs;
        }
    }

    public static PacketV3Metadata parseHeaderV3(byte[] wireBytes) {
        if (wireBytes == null || wireBytes.length < V3_HEADER_LEN + TAG_LEN) {
            throw new IllegalArgumentException("Paquete demasiado corto o corrupto.");
        }
        ByteBuffer buf = ByteBuffer.wrap(wireBytes).order(ByteOrder.BIG_ENDIAN);
        byte version = buf.get();
        if (version != 3) {
            throw new IllegalArgumentException("Versión no soportada: " + version);
        }
        byte flags = buf.get();
        int nodeId = buf.getInt();
        long epoch = buf.getLong();
        long sequence = buf.getLong();
        long timestampMs = buf.getLong();
        return new PacketV3Metadata(version, flags, nodeId, epoch, sequence, timestampMs);
    }
}
