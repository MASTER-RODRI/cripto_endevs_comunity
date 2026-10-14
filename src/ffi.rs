//! Capa de Interoperabilidad Universal C-ABI (`extern "C"`) para C#, C/C++, Java (JNI/JNA/Panama),
//! TypeScript (Node FFI / Deno / Bun / WASM) y Python.
//!
//! Principios de Seguridad DevSecOps en esta frontera FFI:
//! 1. **Prohibición de Unwinding a través de FFI (Mitiga CWE-248):** Toda función `extern "C"` está
//!    envuelta en `std::panic::catch_unwind` para garantizar que ningún pánico interno cruce hacia
//!    el CLR de .NET, la JVM de Java o el runtime de V8.
//! 2. **Cero Asignaciones Cruzadas Peligrosas:** El lenguaje anfitrión (C#, Java, TS, C) provee el
//!    buffer de salida (`out_buf`, `out_cap`) y recibe la longitud exacta escrita en `out_len`.
//!    Así el recolector de basura de C#/Java/TS administra su propia memoria sin fugas de heap entre runtimes.
//! 3. **Limpieza Criptográfica (`Zeroize`):** Al liberar un handle opaco con `cn_mesh_free`, toda la
//!    memoria de claves en Rust se sobrescribe con ceros automáticamente.

#![allow(unsafe_code)]

use std::panic::catch_unwind;
use std::slice;

use crate::{ChronoMeshNode, ChronoWalJournal, DualSlotContainer, Error, MasterSeed, Packet};

/// Handle opaco para `ChronoMeshNode` expuesto a C#, Java, C y TypeScript.
pub struct CnMeshHandle {
    node: ChronoMeshNode,
    wrap_key: [u8; 32],
    dual_slot: DualSlotContainer,
    wal: ChronoWalJournal,
}

impl Drop for CnMeshHandle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.wrap_key.zeroize();
    }
}

unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::FfiParametroInvalido);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn write_output(
    src: &[u8],
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> Result<i32, Error> {
    if out_len.is_null() {
        return Err(Error::FfiParametroInvalido);
    }
    unsafe {
        *out_len = src.len();
    }
    if out_buf.is_null() || out_cap < src.len() {
        return Err(Error::FfiParametroInvalido);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out_buf, src.len());
    }
    Ok(src.len() as i32)
}

/// Genera una semilla maestra de 32 bytes de alta entropía usando el CSPRNG del sistema operativo.
/// Devuelve `0` en éxito o un código negativo (`Error::to_ffi_code`).
#[unsafe(no_mangle)]
pub extern "C" fn cn_generate_master_seed(out_seed_32: *mut u8) -> i32 {
    catch_unwind(|| {
        if out_seed_32.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let seed = MasterSeed::generate();
        unsafe {
            std::ptr::copy_nonoverlapping(seed.as_bytes().as_ptr(), out_seed_32, 32);
        }
        0
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Crea una instancia de `CnMeshHandle` (Nodo distribuido + Contenedor Dual-Slot + WAL).
/// Devuelve un puntero opaco no nulo en éxito, o `null` si los parámetros son inválidos.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_new(
    seed_ptr: *const u8,
    seed_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    node_id: u32,
    boot_epoch: u64,
    max_time_drift_ms: u64,
) -> *mut CnMeshHandle {
    catch_unwind(|| {
        if seed_ptr.is_null() || seed_len != 32 {
            return std::ptr::null_mut();
        }
        let seed_slice = unsafe { slice::from_raw_parts(seed_ptr, 32) };
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed_slice);
        let Ok(seed) = MasterSeed::from_bytes(seed_arr) else {
            return std::ptr::null_mut();
        };
        let Ok(context) = (unsafe { slice_from_raw(context_ptr, context_len) }) else {
            return std::ptr::null_mut();
        };

        let wrap_key = seed.derive_wrap_key(context);
        let node = ChronoMeshNode::new(&seed, context, node_id, boot_epoch, max_time_drift_ms);

        Box::into_raw(Box::new(CnMeshHandle {
            node,
            wrap_key,
            dual_slot: DualSlotContainer::new(),
            wal: ChronoWalJournal::new(),
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Libera de forma segura el handle y limpia todas las claves en memoria (`Zeroize`).
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_free(handle: *mut CnMeshHandle) {
    let _ = catch_unwind(|| {
        if !handle.is_null() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    });
}

/// Cifra un payload en tiempo real (Wire v3: 42 bytes header + payload + 16 bytes tag).
/// Devuelve la cantidad de bytes escritos (`> 0`) o un código de error negativo.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_seal_realtime(
    handle: *const CnMeshHandle,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    now_ms: u64,
    out_packet_buf: *mut u8,
    out_packet_cap: usize,
    out_packet_len: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &*handle };
        let res = (|| -> Result<i32, Error> {
            let pt = unsafe { slice_from_raw(plaintext_ptr, plaintext_len)? };
            let aad = unsafe { slice_from_raw(aad_ptr, aad_len)? };
            let pkt = h.node.seal_realtime(pt, aad, now_ms)?;
            let raw = pkt.to_bytes();
            unsafe { write_output(&raw, out_packet_buf, out_packet_cap, out_packet_len) }
        })();
        match res {
            Ok(written) => written,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Abre y autentica un paquete en tiempo real verificando TTL temporal y ventana anti-replay.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_open_realtime(
    handle: *const CnMeshHandle,
    packet_ptr: *const u8,
    packet_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    now_ms: u64,
    out_plaintext_buf: *mut u8,
    out_plaintext_cap: usize,
    out_plaintext_len: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &*handle };
        let res = (|| -> Result<i32, Error> {
            let pkt_bytes = unsafe { slice_from_raw(packet_ptr, packet_len)? };
            let aad = unsafe { slice_from_raw(aad_ptr, aad_len)? };
            let pkt = Packet::from_bytes(pkt_bytes)?;
            let mut pt = h.node.open_realtime(&pkt, aad, now_ms)?;
            let r =
                unsafe { write_output(&pt, out_plaintext_buf, out_plaintext_cap, out_plaintext_len) };
            use zeroize::Zeroize;
            pt.zeroize();
            r
        })();
        match res {
            Ok(written) => written,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Abre un registro o archivo persistido en el pasado (sin expiración de TTL, ideal tras apagones).
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_open_persisted(
    handle: *const CnMeshHandle,
    packet_ptr: *const u8,
    packet_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_plaintext_buf: *mut u8,
    out_plaintext_cap: usize,
    out_plaintext_len: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &*handle };
        let res = (|| -> Result<i32, Error> {
            let pkt_bytes = unsafe { slice_from_raw(packet_ptr, packet_len)? };
            let aad = unsafe { slice_from_raw(aad_ptr, aad_len)? };
            let pkt = Packet::from_bytes(pkt_bytes)?;
            let mut pt = h.node.open_persisted_record(&pkt, aad)?;
            let r =
                unsafe { write_output(&pt, out_plaintext_buf, out_plaintext_cap, out_plaintext_len) };
            use zeroize::Zeroize;
            pt.zeroize();
            r
        })();
        match res {
            Ok(written) => written,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Cifra un registro y lo empaqueta en un Frame WAL encadenado por SHA-256 listo para append en disco.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_seal_wal_frame(
    handle: *mut CnMeshHandle,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    now_ms: u64,
    out_frame_buf: *mut u8,
    out_frame_cap: usize,
    out_frame_len: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &mut *handle };
        let res = (|| -> Result<i32, Error> {
            let pt = unsafe { slice_from_raw(plaintext_ptr, plaintext_len)? };
            let aad = unsafe { slice_from_raw(aad_ptr, aad_len)? };
            let pkt = h.node.seal_realtime(pt, aad, now_ms)?;
            let frame = h.wal.encode_append_frame(&pkt)?;
            unsafe { write_output(&frame, out_frame_buf, out_frame_cap, out_frame_len) }
        })();
        match res {
            Ok(written) => written,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Exporta un snapshot Dual-Slot A/B resistente a apagones con el estado completo del nodo.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_export_dualslot_state(
    handle: *mut CnMeshHandle,
    out_state_buf: *mut u8,
    out_state_cap: usize,
    out_state_len: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &mut *handle };
        let res = (|| -> Result<i32, Error> {
            let checkpoint = h.node.export_checkpoint(&h.wrap_key)?;
            h.dual_slot.commit_state(&checkpoint, &h.wrap_key)?;
            let bytes = h.dual_slot.to_bytes()?;
            unsafe { write_output(&bytes, out_state_buf, out_state_cap, out_state_len) }
        })();
        match res {
            Ok(written) => written,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Importa y auto-repara el estado del nodo desde un blob Dual-Slot tras un apagón o reinicio.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_import_dualslot_state(
    handle: *mut CnMeshHandle,
    state_ptr: *const u8,
    state_len: usize,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &mut *handle };
        let res = (|| -> Result<i32, Error> {
            let raw = unsafe { slice_from_raw(state_ptr, state_len)? };
            let container = DualSlotContainer::from_bytes(raw)?;
            let (_gen, checkpoint) = container.recover_latest_valid(&h.wrap_key)?;
            h.node.restore_checkpoint(&checkpoint, &h.wrap_key)?;
            h.dual_slot = container;
            Ok(0)
        })();
        match res {
            Ok(code) => code,
            Err(e) => e.to_ffi_code(),
        }
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}

/// Obtiene el hash SHA-256 de integración actual (32 bytes) para auditoría entre nodos.
#[unsafe(no_mangle)]
pub extern "C" fn cn_mesh_get_integrity_sha256(
    handle: *const CnMeshHandle,
    out_sha256_32: *mut u8,
) -> i32 {
    catch_unwind(|| {
        if handle.is_null() || out_sha256_32.is_null() {
            return Error::FfiParametroInvalido.to_ffi_code();
        }
        let h = unsafe { &*handle };
        let sha = h.node.current_integrity_sha256();
        unsafe {
            std::ptr::copy_nonoverlapping(sha.as_ptr(), out_sha256_32, 32);
        }
        0
    })
    .unwrap_or_else(|_| Error::FfiParametroInvalido.to_ffi_code())
}
