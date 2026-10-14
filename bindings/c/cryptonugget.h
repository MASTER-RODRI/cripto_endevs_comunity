/*
 * CryptoNugget v0.5 - C/C++ Header for Universal FFI Integration
 * Compatible with C99, C++, Go (cgo), Python (cffi/ctypes), and JNI.
 */
#ifndef CRYPTONUGGET_H
#define CRYPTONUGGET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CnMeshHandle CnMeshHandle;

/* Error codes returned by FFI functions (< 0 on error) */
#define CN_OK                          0
#define CN_ERR_BASE64                 -1
#define CN_ERR_CORRUPT_PACKET         -2
#define CN_ERR_UNSUPPORTED_VERSION    -3
#define CN_ERR_AUTH_FAILED            -4
#define CN_ERR_UTF8                   -5
#define CN_ERR_CIPHER_OVERFLOW        -6
#define CN_ERR_INVALID_SEED           -7
#define CN_ERR_INVALID_LINK           -8
#define CN_ERR_INVALID_MODE           -9
#define CN_ERR_REPLAY_DETECTED       -10
#define CN_ERR_OUT_OF_WINDOW         -11
#define CN_ERR_UNRESUMED_STATE       -12
#define CN_ERR_TIME_EXPIRED          -13
#define CN_ERR_AAD_TOO_LONG          -14
#define CN_ERR_INTEGRITY_CORRUPTED   -15
#define CN_ERR_FFI_INVALID_PARAM     -16
#define CN_ERR_IO                    -17

int32_t cn_generate_master_seed(uint8_t* out_seed_32);

CnMeshHandle* cn_mesh_new(
    const uint8_t* seed_ptr,
    size_t seed_len,
    const uint8_t* context_ptr,
    size_t context_len,
    uint32_t node_id,
    uint64_t boot_epoch,
    uint64_t max_time_drift_ms
);

void cn_mesh_free(CnMeshHandle* handle);

int32_t cn_mesh_seal_realtime(
    const CnMeshHandle* handle,
    const uint8_t* plaintext_ptr,
    size_t plaintext_len,
    const uint8_t* aad_ptr,
    size_t aad_len,
    uint64_t now_ms,
    uint8_t* out_packet_buf,
    size_t out_packet_cap,
    size_t* out_packet_len
);

int32_t cn_mesh_open_realtime(
    const CnMeshHandle* handle,
    const uint8_t* packet_ptr,
    size_t packet_len,
    const uint8_t* aad_ptr,
    size_t aad_len,
    uint64_t now_ms,
    uint8_t* out_plaintext_buf,
    size_t out_plaintext_cap,
    size_t* out_plaintext_len
);

int32_t cn_mesh_open_persisted(
    const CnMeshHandle* handle,
    const uint8_t* packet_ptr,
    size_t packet_len,
    const uint8_t* aad_ptr,
    size_t aad_len,
    uint8_t* out_plaintext_buf,
    size_t out_plaintext_cap,
    size_t* out_plaintext_len
);

int32_t cn_mesh_seal_wal_frame(
    CnMeshHandle* handle,
    const uint8_t* plaintext_ptr,
    size_t plaintext_len,
    const uint8_t* aad_ptr,
    size_t aad_len,
    uint64_t now_ms,
    uint8_t* out_frame_buf,
    size_t out_frame_cap,
    size_t* out_frame_len
);

int32_t cn_mesh_export_dualslot_state(
    CnMeshHandle* handle,
    uint8_t* out_state_buf,
    size_t out_state_cap,
    size_t* out_state_len
);

int32_t cn_mesh_import_dualslot_state(
    CnMeshHandle* handle,
    const uint8_t* state_ptr,
    size_t state_len
);

int32_t cn_mesh_get_integrity_sha256(
    const CnMeshHandle* handle,
    uint8_t* out_sha256_32
);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTONUGGET_H */
