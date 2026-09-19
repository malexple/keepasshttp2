// P/Invoke boundary to the Zig crypto DLL. All buffer lengths passed across
// this boundary are lengths C# has already validated (exact base64-decoded
// byte counts), never raw lengths taken from the network. The Zig side must
// re-validate them anyway and never trust this process either — defense in
// depth on both sides of the boundary.
//
// NOTE: the exact DLL name/export names/return-code convention here are a
// proposed contract, not yet implemented on the Zig side or verified by a
// build+call round-trip. Treat this file as a draft until we build the Zig
// DLL and confirm the ABI matches (calling convention, nuint vs size_t width,
// export visibility) with an actual isolated test.

using System;
using System.Runtime.InteropServices;

namespace KeePassHttp2.Protocol;

public static class NativeCrypto
{
    private const string LibraryName = "keepass_crypto";

    public const int PublicKeyLength = 32;
    public const int SecretKeyLength = 32;
    public const int NonceLength = 24;
    public const int TagLength = 16;

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe int kp2_box_open(
        byte* ciphertext, nuint ciphertextLen,
        byte* nonce, nuint nonceLen,
        byte* publicKey, nuint publicKeyLen,
        byte* secretKey, nuint secretKeyLen,
        byte* outPlaintext, nuint outPlaintextLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe int kp2_box_seal(
        byte* message, nuint messageLen,
        byte* nonce, nuint nonceLen,
        byte* publicKey, nuint publicKeyLen,
        byte* secretKey, nuint secretKeyLen,
        byte* outCiphertext, nuint outCiphertextLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe void kp2_secure_zero(byte* buf, nuint len);

    public sealed class CryptoException(string reason) : Exception(reason);

    // Decrypts `ciphertext` (must already be exactly nonce/key-validated
    // lengths per ProtocolEnvelopeParser) using senderPublicKey + our own
    // secretKey. Returns freshly allocated plaintext; caller is responsible
    // for zeroing it via SecureZero once no longer needed.
    public static byte[] Open(byte[] ciphertext, byte[] nonce, byte[] senderPublicKey, byte[] secretKey)
    {
        if (nonce.Length != NonceLength)
            throw new ArgumentException($"nonce must be {NonceLength} bytes", nameof(nonce));
        if (senderPublicKey.Length != PublicKeyLength)
            throw new ArgumentException($"publicKey must be {PublicKeyLength} bytes", nameof(senderPublicKey));
        if (secretKey.Length != SecretKeyLength)
            throw new ArgumentException($"secretKey must be {SecretKeyLength} bytes", nameof(secretKey));
        if (ciphertext.Length < TagLength)
            throw new ArgumentException("ciphertext shorter than auth tag", nameof(ciphertext));

        var plaintext = new byte[ciphertext.Length - TagLength];

        unsafe
        {
            fixed (byte* c = ciphertext, n = nonce, pk = senderPublicKey, sk = secretKey, m = plaintext)
            {
                int result = kp2_box_open(
                    c, (nuint)ciphertext.Length,
                    n, (nuint)nonce.Length,
                    pk, (nuint)senderPublicKey.Length,
                    sk, (nuint)secretKey.Length,
                    m, (nuint)plaintext.Length);

                if (result < 0)
                {
                    SecureZero(plaintext);
                    throw new CryptoException($"kp2_box_open failed with code {result}");
                }
            }
        }

        return plaintext;
    }

    // Encrypts `message` for recipientPublicKey, signed with our secretKey.
    public static byte[] Seal(byte[] message, byte[] nonce, byte[] recipientPublicKey, byte[] secretKey)
    {
        if (nonce.Length != NonceLength)
            throw new ArgumentException($"nonce must be {NonceLength} bytes", nameof(nonce));
        if (recipientPublicKey.Length != PublicKeyLength)
            throw new ArgumentException($"publicKey must be {PublicKeyLength} bytes", nameof(recipientPublicKey));
        if (secretKey.Length != SecretKeyLength)
            throw new ArgumentException($"secretKey must be {SecretKeyLength} bytes", nameof(secretKey));

        var ciphertext = new byte[message.Length + TagLength];

        unsafe
        {
            fixed (byte* m = message, n = nonce, pk = recipientPublicKey, sk = secretKey, c = ciphertext)
            {
                int result = kp2_box_seal(
                    m, (nuint)message.Length,
                    n, (nuint)nonce.Length,
                    pk, (nuint)recipientPublicKey.Length,
                    sk, (nuint)secretKey.Length,
                    c, (nuint)ciphertext.Length);

                if (result < 0)
                    throw new CryptoException($"kp2_box_seal failed with code {result}");
            }
        }

        return ciphertext;
    }

    // Best-effort defense against memory scraping: overwrite plaintext
    // buffers as soon as they are no longer needed. Calls into Zig's
    // std.crypto.secureZero so the write cannot be optimized away, unlike
    // a plain Array.Clear which the JIT is free to elide if it can prove
    // the buffer is otherwise unused.
    public static void SecureZero(byte[] buffer)
    {
        unsafe
        {
            fixed (byte* p = buffer)
            {
                kp2_secure_zero(p, (nuint)buffer.Length);
            }
        }
    }
}
