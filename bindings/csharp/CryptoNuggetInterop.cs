// ============================================================================
// CryptoNugget v0.5 - Wrapper Oficial de Alto Rendimiento para C# / .NET 8+
// ============================================================================
// Características:
// - Uso de SafeHandle para garantizar liberación determinista (cn_mesh_free) e
//   impedir fugas de memoria o claves incluso ante excepciones de .NET.
// - Uso de Span<byte> / ReadOnlySpan<byte> y ArrayPool<byte> para cero presión al GC.
// - Persistencia Atómica en Disco con Temp-File + FileOptions.WriteThrough + Replace
//   combinada con el contenedor Dual-Slot A/B de Rust.

using System;
using System.Buffers;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CryptoNugget.Interop
{
    public enum CryptoNuggetErrorCode : int
    {
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
        Io = -17
    }

    public sealed class CryptoNuggetException : Exception
    {
        public CryptoNuggetErrorCode ErrorCode { get; }

        public CryptoNuggetException(CryptoNuggetErrorCode code)
            : base($"Error criptográfico en CryptoNugget nativo: {code} ({(int)code})")
        {
            ErrorCode = code;
        }
    }

    internal static unsafe partial class NativeMethods
    {
        private const string DllName = "cripto_endevs_comunity";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_generate_master_seed(byte* outSeed32);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern IntPtr cn_mesh_new(
            byte* seedPtr, nuint seedLen,
            byte* contextPtr, nuint contextLen,
            uint nodeId, ulong bootEpoch, ulong maxTimeDriftMs);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void cn_mesh_free(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_seal_realtime(
            IntPtr handle,
            byte* plaintextPtr, nuint plaintextLen,
            byte* aadPtr, nuint aadLen,
            ulong nowMs,
            byte* outPacketBuf, nuint outPacketCap, out nuint outPacketLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_open_realtime(
            IntPtr handle,
            byte* packetPtr, nuint packetLen,
            byte* aadPtr, nuint aadLen,
            ulong nowMs,
            byte* outPlaintextBuf, nuint outPlaintextCap, out nuint outPlaintextLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_open_persisted(
            IntPtr handle,
            byte* packetPtr, nuint packetLen,
            byte* aadPtr, nuint aadLen,
            byte* outPlaintextBuf, nuint outPlaintextCap, out nuint outPlaintextLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_seal_wal_frame(
            IntPtr handle,
            byte* plaintextPtr, nuint plaintextLen,
            byte* aadPtr, nuint aadLen,
            ulong nowMs,
            byte* outFrameBuf, nuint outFrameCap, out nuint outFrameLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_export_dualslot_state(
            IntPtr handle,
            byte* outStateBuf, nuint outStateCap, out nuint outStateLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_import_dualslot_state(
            IntPtr handle,
            byte* statePtr, nuint stateLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int cn_mesh_get_integrity_sha256(
            IntPtr handle,
            byte* outSha256_32);
    }

    internal sealed class CnMeshSafeHandle : SafeHandle
    {
        public CnMeshSafeHandle(IntPtr handle) : base(IntPtr.Zero, ownsHandle: true)
        {
            SetHandle(handle);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            NativeMethods.cn_mesh_free(handle);
            return true;
        }
    }

    /// <summary>
    /// Cliente distribuido ChronoMesh para .NET con soporte en tiempo real y persistencia inmune a apagones.
    /// Thread-safe para operaciones de cifrado y descifrado en paralelo.
    /// </summary>
    public sealed unsafe class ChronoMeshClient : IDisposable
    {
        private const int WireV3Overhead = 42 + 16; // 42B Header + 16B GCM Tag
        private const int WalFrameOverhead = 72 + WireV3Overhead;
        private readonly CnMeshSafeHandle _handle;

        public ChronoMeshClient(
            ReadOnlySpan<byte> masterSeed32,
            string contextDomain,
            uint nodeId,
            ulong bootEpoch,
            ulong maxTimeDriftMs = 30_000)
        {
            if (masterSeed32.Length != 32)
                throw new ArgumentException("La semilla maestra debe tener exactamente 32 bytes.", nameof(masterSeed32));

            byte[] ctxBytes = Encoding.UTF8.GetBytes(contextDomain);
            fixed (byte* sPtr = masterSeed32)
            fixed (byte* cPtr = ctxBytes)
            {
                IntPtr ptr = NativeMethods.cn_mesh_new(
                    sPtr, (nuint)masterSeed32.Length,
                    cPtr, (nuint)ctxBytes.Length,
                    nodeId, bootEpoch, maxTimeDriftMs);

                if (ptr == IntPtr.Zero)
                    throw new CryptoNuggetException(CryptoNuggetErrorCode.SemillaInvalida);

                _handle = new CnMeshSafeHandle(ptr);
            }
        }

        public static byte[] GenerateMasterSeed()
        {
            byte[] seed = new byte[32];
            fixed (byte* ptr = seed)
            {
                int rc = NativeMethods.cn_generate_master_seed(ptr);
                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
            }
            return seed;
        }

        public byte[] SealRealtime(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, ulong? nowMs = null)
        {
            ulong ts = nowMs ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            int cap = plaintext.Length + WireV3Overhead;
            byte[] output = new byte[cap];

            fixed (byte* ptPtr = plaintext)
            fixed (byte* aadPtr = aad)
            fixed (byte* outPtr = output)
            {
                int rc = NativeMethods.cn_mesh_seal_realtime(
                    _handle.DangerousGetHandle(),
                    ptPtr, (nuint)plaintext.Length,
                    aadPtr, (nuint)aad.Length,
                    ts,
                    outPtr, (nuint)cap, out nuint written);

                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
                return output.Length == (int)written ? output : output.AsSpan(0, (int)written).ToArray();
            }
        }

        public byte[] OpenRealtime(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> aad, ulong? nowMs = null)
        {
            if (packet.Length < WireV3Overhead)
                throw new CryptoNuggetException(CryptoNuggetErrorCode.PaqueteCorrupto);

            ulong ts = nowMs ?? (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            int cap = packet.Length - WireV3Overhead;
            byte[] output = new byte[Math.Max(cap, 1)];

            fixed (byte* pktPtr = packet)
            fixed (byte* aadPtr = aad)
            fixed (byte* outPtr = output)
            {
                int rc = NativeMethods.cn_mesh_open_realtime(
                    _handle.DangerousGetHandle(),
                    pktPtr, (nuint)packet.Length,
                    aadPtr, (nuint)aad.Length,
                    ts,
                    outPtr, (nuint)output.Length, out nuint written);

                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
                return output.AsSpan(0, (int)written).ToArray();
            }
        }

        public byte[] OpenPersistedRecord(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> aad)
        {
            if (packet.Length < WireV3Overhead)
                throw new CryptoNuggetException(CryptoNuggetErrorCode.PaqueteCorrupto);

            int cap = packet.Length - WireV3Overhead;
            byte[] output = new byte[Math.Max(cap, 1)];

            fixed (byte* pktPtr = packet)
            fixed (byte* aadPtr = aad)
            fixed (byte* outPtr = output)
            {
                int rc = NativeMethods.cn_mesh_open_persisted(
                    _handle.DangerousGetHandle(),
                    pktPtr, (nuint)packet.Length,
                    aadPtr, (nuint)aad.Length,
                    outPtr, (nuint)output.Length, out nuint written);

                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
                return output.AsSpan(0, (int)written).ToArray();
            }
        }

        /// <summary>
        /// Guarda un checkpoint Dual-Slot en disco con descarga física forzada (WriteThrough)
        /// para sobrevivir apagones eléctricos sin corromper el archivo de estado.
        /// </summary>
        public void SaveStateAtomicallyToDisk(string filePath)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                nuint written;
                fixed (byte* outPtr = buffer)
                {
                    int rc = NativeMethods.cn_mesh_export_dualslot_state(
                        _handle.DangerousGetHandle(),
                        outPtr, (nuint)buffer.Length, out written);
                    if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
                }

                string tempPath = filePath + ".tmp";
                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    fs.Write(buffer, 0, (int)written);
                    fs.Flush(flushToDisk: true);
                }

                if (File.Exists(filePath))
                    File.Replace(tempPath, filePath, destinationBackupFileName: filePath + ".bak", ignoreMetadataErrors: true);
                else
                    File.Move(tempPath, filePath);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public void RestoreStateFromDisk(string filePath)
        {
            byte[] raw = File.ReadAllBytes(filePath);
            fixed (byte* ptr = raw)
            {
                int rc = NativeMethods.cn_mesh_import_dualslot_state(
                    _handle.DangerousGetHandle(), ptr, (nuint)raw.Length);
                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
            }
        }

        public byte[] GetIntegritySha256()
        {
            byte[] sha = new byte[32];
            fixed (byte* ptr = sha)
            {
                int rc = NativeMethods.cn_mesh_get_integrity_sha256(_handle.DangerousGetHandle(), ptr);
                if (rc < 0) throw new CryptoNuggetException((CryptoNuggetErrorCode)rc);
            }
            return sha;
        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}
