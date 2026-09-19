// Isolated round-trip test for the P/Invoke boundary to keepass_crypto.dll.
// Uses the exact same PyNaCl-generated vector as ws_box_test.zig, so a
// MATCH here proves the full chain PyNaCl -> C# -> P/Invoke -> Zig works,
// not just the crypto primitive in isolation.
//
// Setup:
//   1. zig build-lib keepass_crypto.zig -dynamic -femit-bin=keepass_crypto.dll
//   2. Copy keepass_crypto.dll next to this project's compiled .exe
//      (e.g. bin/Debug/net8.0/) or anywhere on PATH.
//   3. dotnet run

using System;
using KeePassHttp2.Protocol;

byte[] alicePk = Convert.FromHexString("d2ac154d5dbe5d89f2c6873cca12c420a095f27a6d8e59aa0015b5ac5aaf065f");
byte[] aliceSk = Convert.FromHexString("d6a0db7579b4308044734b8d5f0a238d8d295f7523b6ae74a48f165aad7f823e");
byte[] bobPk = Convert.FromHexString("5731d554ef6565da6b07be964ab059a27373de39c7b0115831eb7e9542339277");
byte[] bobSk = Convert.FromHexString("201dbc619fa65bac4a04fa606c93db43251bf3f104c50c9cf7e1ae64fa7f7b56");
byte[] nonce = Convert.FromHexString("a554a94635a6a689b507415bc390602f500aa495fc61e623");
byte[] message = Convert.FromHexString("48656c6c6f204b65655061737348545450322066726f6d2050794e61436c");
byte[] expectedCiphertext = Convert.FromHexString(
    "e7d7bed288642e0ef60a9683753cb9a6127f7a0c93801c74603579029270f69cc91cbb9868751ca0b1fbf05c029f");

Console.WriteLine($"alicePk: {alicePk.Length} bytes, bobSk: {bobSk.Length} bytes, nonce: {nonce.Length} bytes, ciphertext: {expectedCiphertext.Length} bytes");

// Alice seals for Bob: her secret key + his public key.
byte[] ciphertext = NativeCrypto.Seal(message, nonce, bobPk, aliceSk);
bool sealMatch = ciphertext.AsSpan().SequenceEqual(expectedCiphertext);
Console.WriteLine($"SEAL vs PyNaCl ciphertext: {(sealMatch ? "MATCH" : "MISMATCH")}");
if (!sealMatch)
{
    Console.WriteLine($"got:      {Convert.ToHexString(ciphertext)}");
    Console.WriteLine($"expected: {Convert.ToHexString(expectedCiphertext)}");
}

// Bob opens using his secret key + Alice's public key.
byte[] plaintext = NativeCrypto.Open(expectedCiphertext, nonce, alicePk, bobSk);
bool openMatch = plaintext.AsSpan().SequenceEqual(message);
Console.WriteLine($"OPEN vs original message: {(openMatch ? "MATCH" : "MISMATCH")}");
if (!openMatch)
{
    Console.WriteLine($"got:      {Convert.ToHexString(plaintext)}");
    Console.WriteLine($"expected: {Convert.ToHexString(message)}");
}

NativeCrypto.SecureZero(plaintext);
