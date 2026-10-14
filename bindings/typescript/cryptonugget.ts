/**
 * CryptoNugget v0.5 - Wrapper Universal para TypeScript (Node.js / Bun / Deno / WebAssembly)
 *
 * Permite que el Frontend Web, Edge Workers y microservicios Node.js hablen en tiempo real
 * el protocolo binario Wire v3 (Big-Endian) con los servicios en C#, Rust y Java.
 */

export enum CryptoNuggetErrorCode {
  Ok = 0,
  Base64 = -1,
  PaqueteCorrupto = -2,
  VersionNoSoportada = -3,
  Autenticacion = -4,
  Utf8 = -5,
  Cifrado = -6,
  SemillaInvalida = -7,
  EnlaceInvalido = -8,
  ModoInvalido = -9,
  Repetido = -10,
  FueraDeOrden = -11,
  EstadoSinReanudar = -12,
  TiempoExpiradoOInvalido = -13,
  AadDemasiadoLargo = -14,
  IntegridadContextoCorrupta = -15,
  FfiParametroInvalido = -16,
}

export interface PacketV3Header {
  version: number;
  flags: number;
  nodeId: number;
  epoch: bigint;
  sequence: bigint;
  timestampMs: bigint;
  nonce: Uint8Array;
}

export const V3_HEADER_LEN = 42;
export const GCM_TAG_LEN = 16;

/**
 * Inspector sin copia (Zero-Copy) de paquetes Wire v3 en TypeScript para enrutamiento
 * rápido en API Gateways, WebSockets o Workers antes o después de pasar por FFI/WASM.
 */
export function inspectPacketV3Header(packetBytes: Uint8Array): PacketV3Header {
  if (packetBytes.byteLength < V3_HEADER_LEN + GCM_TAG_LEN) {
    throw new Error(`Paquete corrupto: longitud ${packetBytes.byteLength} menor al mínimo de 58 bytes`);
  }
  const view = new DataView(packetBytes.buffer, packetBytes.byteOffset, packetBytes.byteLength);
  const version = view.getUint8(0);
  if (version !== 3) {
    throw new Error(`Versión de paquete no soportada en inspector v3: ${version}`);
  }
  return {
    version,
    flags: view.getUint8(1),
    nodeId: view.getUint32(2, false),       // Big-Endian
    epoch: view.getBigUint64(6, false),     // Big-Endian
    sequence: view.getBigUint64(14, false), // Big-Endian
    timestampMs: view.getBigUint64(22, false), // Big-Endian
    nonce: packetBytes.subarray(30, 42),
  };
}

/**
 * Interfaz del módulo nativo/WASM compilado desde `src/ffi.rs`.
 */
export interface CryptoNuggetNativeExports {
  memory: WebAssembly.Memory;
  cn_mesh_new(
    seedPtr: number, seedLen: number,
    ctxPtr: number, ctxLen: number,
    nodeId: number, bootEpoch: bigint, maxDriftMs: bigint
  ): number;
  cn_mesh_free(handle: number): void;
  cn_mesh_seal_realtime(
    handle: number,
    ptPtr: number, ptLen: number,
    aadPtr: number, aadLen: number,
    nowMs: bigint,
    outBuf: number, outCap: number, outLenPtr: number
  ): number;
  cn_mesh_open_realtime(
    handle: number,
    pktPtr: number, pktLen: number,
    aadPtr: number, aadLen: number,
    nowMs: bigint,
    outBuf: number, outCap: number, outLenPtr: number
  ): number;
  cn_mesh_open_persisted(
    handle: number,
    pktPtr: number, pktLen: number,
    aadPtr: number, aadLen: number,
    outBuf: number, outCap: number, outLenPtr: number
  ): number;
}
