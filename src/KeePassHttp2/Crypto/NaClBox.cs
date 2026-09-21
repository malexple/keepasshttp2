// Thin adapter over the vendored Chaos.NaCl primitives, providing the
// crypto_box (X25519 + XSalsa20-Poly1305) API shape our protocol code needs.
// This replaces the old P/Invoke-based NativeCrypto.cs - everything here is
// pure managed C#, no native DLL, no NuGet package.
//
// We do NOT vendor Chaos.NaCl/MontgomeryCurve25519.cs. That file's
// GetPublicKey uses the Edwards-curve fast path (GroupOperations.
// ge_scalarmult_base + EdwardsToMontgomeryX), which needs the full Ed25519
// group-element/precomputed-table machinery (used only for EdDSA
// signatures, which we don't need) - and since that method lives in the
// same file as KeyExchange, the whole file fails to compile without also
// vendoring that machinery. So instead we reimplement KeyExchange's ~4
// lines directly here, using only primitives we did vendor
// (MontgomeryOperations.scalarmult + Salsa20.HSalsa20). Public key
// derivation uses the same Montgomery ladder applied to the standard
// X25519 base point (9) - mathematically identical per RFC 7748, verified
// against Chaos.NaCl's own official Alice/Bob/Frank test vectors in
// CryptoTests.cs.

using System;
using System.Security.Cryptography;
using Chaos.NaCl;
using Chaos.NaCl.Internal.Ed25519Ref10;
using Chaos.NaCl.Internal.Salsa;

namespace KeePassHttp2.Crypto;

public static class NaClBox
{
    public const int PublicKeyLength = 32;
    public const int SecretKeyLength = 32;
    public const int NonceLength = 24;
    public const int TagLength = 16;

    private static readonly byte[] BasePoint = new byte[32]
    {
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    private static readonly byte[] Zero16 = new byte[16];

    public sealed class CryptoException(string reason) : Exception(reason);

    public static (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        var secretKey = new byte[SecretKeyLength];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(secretKey);

        return (GetPublicKey(secretKey), secretKey);
    }

    public static byte[] GetPublicKey(byte[] secretKey)
    {
        if (secretKey.Length != SecretKeyLength)
            throw new ArgumentException($"secretKey must be {SecretKeyLength} bytes", nameof(secretKey));

        var publicKey = new byte[PublicKeyLength];
        MontgomeryOperations.scalarmult(publicKey, 0, secretKey, 0, BasePoint, 0);
        return publicKey;
    }

    // Equivalent to crypto_box_beforenm: raw X25519 ECDH output, hashed
    // through HSalsa20 with an all-zero 16-byte nonce (this is exactly
    // what NaCl's own MontgomeryCurve25519.KeyExchange does internally).
    public static byte[] KeyExchange(byte[] theirPublicKey, byte[] ourSecretKey)
    {
        if (theirPublicKey.Length != PublicKeyLength)
            throw new ArgumentException($"publicKey must be {PublicKeyLength} bytes", nameof(theirPublicKey));
        if (ourSecretKey.Length != SecretKeyLength)
            throw new ArgumentException($"secretKey must be {SecretKeyLength} bytes", nameof(ourSecretKey));

        var sharedKey = new byte[SecretKeyLength];
        MontgomeryOperations.scalarmult(sharedKey, 0, ourSecretKey, 0, theirPublicKey, 0);
        Salsa20.HSalsa20(sharedKey, 0, sharedKey, 0, Zero16, 0);
        return sharedKey;
    }

    public static byte[] Seal(byte[] message, byte[] nonce, byte[] recipientPublicKey, byte[] secretKey)
    {
        if (nonce.Length != NonceLength)
            throw new ArgumentException($"nonce must be {NonceLength} bytes", nameof(nonce));

        var sharedKey = KeyExchange(recipientPublicKey, secretKey);
        try
        {
            return XSalsa20Poly1305.Encrypt(message, sharedKey, nonce);
        }
        finally
        {
            CryptoBytes.Wipe(sharedKey);
        }
    }

    public static byte[] Open(byte[] ciphertext, byte[] nonce, byte[] senderPublicKey, byte[] secretKey)
    {
        if (nonce.Length != NonceLength)
            throw new ArgumentException($"nonce must be {NonceLength} bytes", nameof(nonce));

        var sharedKey = KeyExchange(senderPublicKey, secretKey);
        try
        {
            var plaintext = XSalsa20Poly1305.TryDecrypt(ciphertext, sharedKey, nonce);
            if (plaintext is null)
                throw new CryptoException("decryption failed (authentication tag mismatch)");
            return plaintext;
        }
        finally
        {
            CryptoBytes.Wipe(sharedKey);
        }
    }

    public static void SecureZero(byte[] buffer) => CryptoBytes.Wipe(buffer);
}