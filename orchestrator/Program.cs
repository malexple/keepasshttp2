// End-to-end orchestrator. Transport (NativeWebSocket) + outer protocol
// (ProtocolEnvelopeParser) + crypto (NativeCrypto) + replay defense
// (NonceTracker) + inner protocol (InnerMessages) are all real. get-logins
// now queries a real KeePassLib database instead of returning a stub.
//
// TEMPORARY: this process opens its own .kdbx via a console prompt, because
// it is not yet wired up as a real KeePass IPlugin (no IPluginHost, so no
// access to the database the user already has open in the KeePass UI).
// That is the next planned step. Until then, do NOT point this at a real
// production database — the master password is typed in plaintext on the
// console with no masking.
//
// Assumption (flagged, not yet verified against a real extension): the
// change-public-keys response shape is
//   {"action":"change-public-keys","publicKey":"<host pk b64>","success":"true","version":"..."}
// and get-logins response shape is
//   {"count":N,"entries":[{"login":"...","password":"...","name":"...","uuid":"..."}],"success":"true"}
// These follow the community-documented protocol but have not been
// cross-checked against a real browser handshake yet.
//
// URL matching (simplified, not the full KeePassXC-Browser algorithm):
// matches an entry if its stored URL's host equals the requested URL's
// host, case-insensitively. Ignores scheme, port, and path.
//
// Run: dotnet run

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KeePassHttp2.Protocol;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;

Console.Write("KeePass database path: ");
string dbPath = Console.ReadLine() ?? throw new InvalidOperationException("no path given");
Console.Write("Master password: ");
string masterPassword = Console.ReadLine() ?? throw new InvalidOperationException("no password given");

var db = new PwDatabase();
{
    var ioc = IOConnectionInfo.FromPath(dbPath);
    var key = new CompositeKey();
    key.AddUserKey(new KcpPassword(masterPassword));
    db.Open(ioc, key, null);
    Console.WriteLine($"KeePass database opened: {db.Name} ({db.RootGroup.GetEntries(true).UCount} entries)");
}

var (hostPublicKey, hostSecretKey) = NativeCrypto.GenerateKeyPair();
Console.WriteLine($"Host public key: {Convert.ToBase64String(hostPublicKey)}");

var clientPublicKeys = new Dictionary<string, byte[]>(); // clientID -> public key, in-memory only
var nonceTracker = new NonceTracker();

// net48 has no RandomNumberGenerator.GetBytes(int) static convenience
// method (added in .NET 6); use a single shared RNG instance instead.
using var rng = RandomNumberGenerator.Create();

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

    byte[] responseNonce = new byte[NativeCrypto.NonceLength];
    rng.GetBytes(responseNonce);
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
    Console.WriteLine($"get-logins for url={request?.Url}");

    var matches = new List<object>();

    if (!string.IsNullOrEmpty(request?.Url) && Uri.TryCreate(request.Url, UriKind.Absolute, out var requestUri))
    {
        foreach (var entry in db.RootGroup.GetEntries(true))
        {
            string entryUrl = entry.Strings.ReadSafe(PwDefs.UrlField);
            if (string.IsNullOrEmpty(entryUrl)) continue;
            if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var entryUri)) continue;

            if (!string.Equals(entryUri.Host, requestUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;

            matches.Add(new
            {
                login = entry.Strings.ReadSafe(PwDefs.UserNameField),
                password = entry.Strings.ReadSafe(PwDefs.PasswordField),
                name = entry.Strings.ReadSafe(PwDefs.TitleField),
                uuid = entry.Uuid.ToHexString(),
            });
        }
    }

    return new
    {
        count = matches.Count,
        entries = matches,
        success = "true",
    };
}

void SendJson(int handle, object payload)
{
    string json = JsonSerializer.Serialize(payload);
    Console.WriteLine($"sending: {json}");
    NativeWebSocket.Send(handle, Encoding.UTF8.GetBytes(json));
}
