// End-to-end orchestrator with stubbed business logic (no real KeePassLib
// yet). Wires together: NativeWebSocket (transport), ProtocolEnvelopeParser
// (outer JSON), NativeCrypto (crypto_box), NonceTracker (replay defense),
// InnerMessages (inner JSON).
//
// Supported actions (stubs only):
//   change-public-keys : real key exchange, stores the client's public key
//                          in memory for this run only (not persisted).
//   get-logins          : always returns one fake entry, ignores the
//                          "keys" association list entirely for now.
//
// Assumption (flagged, not yet verified against a real extension): the
// change-public-keys response shape is
//   {"action":"change-public-keys","publicKey":"<host pk b64>","success":"true","version":"..."}
// and get-logins response shape is
//   {"count":1,"entries":[{"login":"...","password":"...","name":"..."}],"success":"true"}
// These follow the community-documented protocol but have not been
// cross-checked against a real browser handshake yet.
//
// Run: dotnet run

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KeePassHttp2.Protocol;

var (hostPublicKey, hostSecretKey) = NativeCrypto.GenerateKeyPair();
Console.WriteLine($"Host public key: {Convert.ToBase64String(hostPublicKey)}");

var clientPublicKeys = new Dictionary<string, byte[]>(); // clientID -> public key, in-memory only
var nonceTracker = new NonceTracker();

NativeWebSocket.Listen(19455);
Console.WriteLine("Listening on 127.0.0.1:19455 (orchestrator)");

while (true)
{
    Console.WriteLine("Waiting for a connection...");
    int handle = NativeWebSocket.Accept();
    if (handle < 0)
    {
        Console.WriteLine($"accept failed/rejected: code {handle}");
        continue;
    }
    Console.WriteLine($"Connection accepted, handle={handle}");

    while (true)
    {
        byte[]? raw = NativeWebSocket.Recv(handle);
        if (raw is null)
        {
            Console.WriteLine("connection closed");
            break;
        }

        string rawJson = Encoding.UTF8.GetString(raw);
        Console.WriteLine($"received envelope: {rawJson}");

        try
        {
            HandleEnvelope(handle, rawJson);
        }
        catch (EnvelopeValidationException ex)
        {
            Console.WriteLine($"REJECTED: {ex.Message}");
            // Per protocol, malformed/rejected requests just get no useful
            // response; a real implementation would send an error envelope.
        }
        catch (NativeCrypto.CryptoException ex)
        {
            Console.WriteLine($"CRYPTO ERROR: {ex.Message}");
        }
    }
}

void HandleEnvelope(int handle, string rawJson)
{
    var envelope = ProtocolEnvelopeParser.Parse(rawJson);
    var kind = ProtocolEnvelopeParser.Classify(envelope);

    if (kind == EnvelopeKind.ChangePublicKeys)
    {
        HandleChangePublicKeys(handle, envelope);
        return;
    }

    HandleEncrypted(handle, envelope);
}

void HandleChangePublicKeys(int handle, ProtocolEnvelope envelope)
{
    byte[] clientPk = ProtocolEnvelopeParser.DecodeFixedLength(
        envelope.PublicKey!, NativeCrypto.PublicKeyLength, "publicKey");

    clientPublicKeys[envelope.ClientId!] = clientPk;
    Console.WriteLine($"stored public key for clientID={envelope.ClientId}");

    var response = new
    {
        action = "change-public-keys",
        publicKey = Convert.ToBase64String(hostPublicKey),
        success = "true",
        version = "2.0.0-stub",
    };

    SendJson(handle, response);
}

void HandleEncrypted(int handle, ProtocolEnvelope envelope)
{
    if (!clientPublicKeys.TryGetValue(envelope.ClientId!, out var clientPk))
        throw new EnvelopeValidationException($"unknown clientID: {envelope.ClientId}");

    if (nonceTracker.IsReplay(envelope.ClientId!, envelope.Nonce!))
        throw new EnvelopeValidationException("nonce replay detected");

    byte[] nonce = ProtocolEnvelopeParser.DecodeFixedLength(envelope.Nonce!, NativeCrypto.NonceLength, "nonce");
    byte[] ciphertext = Convert.FromBase64String(envelope.Message!);

    byte[] plaintext = NativeCrypto.Open(ciphertext, nonce, clientPk, hostSecretKey);
    nonceTracker.Register(envelope.ClientId!, envelope.Nonce!); // only after successful auth

    string innerJson = Encoding.UTF8.GetString(plaintext);
    NativeCrypto.SecureZero(plaintext);
    Console.WriteLine($"decrypted inner: {innerJson}");

    var probe = JsonSerializer.Deserialize<InnerActionProbe>(innerJson)
        ?? throw new EnvelopeValidationException("empty inner message");

    object innerResponse = probe.Action switch
    {
        "get-logins" => HandleGetLogins(innerJson),
        _ => throw new EnvelopeValidationException($"unhandled inner action: {probe.Action}"),
    };

    string innerResponseJson = JsonSerializer.Serialize(innerResponse);
    byte[] innerResponseBytes = Encoding.UTF8.GetBytes(innerResponseJson);

    byte[] responseNonce = RandomNumberGenerator.GetBytes(NativeCrypto.NonceLength);
    byte[] responseCiphertext = NativeCrypto.Seal(innerResponseBytes, responseNonce, clientPk, hostSecretKey);
    NativeCrypto.SecureZero(innerResponseBytes);

    var outerResponse = new
    {
        action = probe.Action,
        message = Convert.ToBase64String(responseCiphertext),
        nonce = Convert.ToBase64String(responseNonce),
        clientID = envelope.ClientId,
    };

    SendJson(handle, outerResponse);
}

object HandleGetLogins(string innerJson)
{
    var request = JsonSerializer.Deserialize<GetLoginsRequest>(innerJson);
    Console.WriteLine($"get-logins stub for url={request?.Url}");

    return new
    {
        count = 1,
        entries = new[]
        {
            new { login = "stub-user", password = "stub-password", name = "Stub Entry", uuid = "00000000000000000000000000000000" },
        },
        success = "true",
    };
}

void SendJson(int handle, object payload)
{
    string json = JsonSerializer.Serialize(payload);
    Console.WriteLine($"sending: {json}");
    NativeWebSocket.Send(handle, Encoding.UTF8.GetBytes(json));
}
