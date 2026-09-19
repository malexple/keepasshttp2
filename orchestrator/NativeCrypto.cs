// P/Invoke boundary to the Zig crypto DLL.

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

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe int kp2_generate_keypair(
        byte* outPublic, nuint outPublicLen,
        byte* outSecret, nuint outSecretLen);

    public sealed class CryptoException(string reason) : Exception(reason);

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

    public static (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair()
    {
        var publicKey = new byte[PublicKeyLength];
        var secretKey = new byte[SecretKeyLength];

        unsafe
        {
            fixed (byte* pk = publicKey, sk = secretKey)
            {
                int result = kp2_generate_keypair(pk, (nuint)publicKey.Length, sk, (nuint)secretKey.Length);
                if (result != 0)
                    throw new CryptoException($"kp2_generate_keypair failed with code {result}");
            }
        }

        return (publicKey, secretKey);
    }
}
