// Real KeePass plugin entry point. KeePass discovers this by scanning DLLs
// in its Plugins folder for a public class deriving from KeePass.Plugins.Plugin.
//
// Naming convention (required by KeePass, not optional): the assembly file
// name (without extension) must equal this class's namespace, and the
// class must be named "<Namespace>Ext". KeePassHttp2.csproj's
// <AssemblyName> must match this - see that file.
//
// This is the fully-managed port of the old orchestrator/KeePassHttp2Ext.cs:
//   - NativeCrypto (P/Invoke into a Zig DLL)   -> KeePassHttp2.Crypto.NaClBox
//   - NativeWebSocket (P/Invoke into a Zig DLL) -> KeePassHttp2.Transport.WebSocketServer
//   - System.Text.Json                          -> KeePassHttp2.Json (hand-rolled)
// Protocol logic (envelope parsing, nonce replay tracking, action
// dispatch) is unchanged from the orchestrator version.
//
// Lifecycle:
//   Initialize(host) - called by KeePass at startup/plugin load. Must
//     return quickly, so the WebSocket accept/recv loop runs on a
//     background thread, not here.
//   Terminate() - called at shutdown/plugin unload. Signals the loop to
//     stop, disposes any in-flight connection (see _activeConnection
//     below), and joins the thread with a timeout.
//
// Thread-safety: PwDatabase/PwEntry are not thread-safe and are owned by
// the UI thread. All access to host.Database is marshaled onto the UI
// thread via host.MainWindow.Invoke(...).
//
// _activeConnection and Terminate(): WebSocketServer.Shutdown() only
// stops HttpListener from accepting *new* connections (verified in
// TransportTests.Shutdown_UnblocksPendingAccept) - it does not touch an
// already-established WebSocketConnection that a client opened and then
// went idle on. Without this, Terminate() could hang KeePass on exit
// whenever a browser extension connection is open but not actively
// sending. So we track the current connection and Dispose() it here too:
// that aborts the pending ReceiveAsync with ObjectDisposedException,
// which WebSocketConnection.Receive() already catches and turns into a
// clean null return, letting ServerLoop's inner loop exit on its own.
//
// Trust model (change-public-keys / associate / test-associate):
// change-public-keys is free for anyone to call - it's just an ephemeral
// key exchange, no secrets. associate is the actual trust boundary: it
// pops up AssociateDialog on the KeePass UI thread, and nothing proceeds
// until a human clicks Allow. Once allowed, the client's permanent
// identification public key is stored in the open database's CustomData
// (survives KeePass restarts), and test-associate on a later connection
// just looks it up and compares - this matches how KeePassXC-Browser
// itself does it (see keepassxc-protocol.md), including its known
// limitation that test-associate is a plain key comparison, not a fresh
// challenge-response proof of possession.
//
// associate and test-associate both always send back a real
// success:true/false response rather than throwing - unlike most of our
// other error paths, "no database open" and "user declined pairing" are
// expected, common outcomes here (not protocol violations), and a real
// client needs an actual answer instead of a silent timeout to decide
// whether to retry, give up, or prompt the user again.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Chaos.NaCl;
using KeePass.Plugins;
using KeePassHttp2.Crypto;
using KeePassHttp2.Json;
using KeePassHttp2.Protocol;
using KeePassHttp2.Transport;
using KeePassHttp2.UI;
using KeePassLib;

namespace KeePassHttp2;

public sealed class KeePassHttp2Ext : Plugin
{
    private const ushort ListenPort = 19455;
    private const string ProtocolVersion = "2.0.0-stub";
    private const string CustomDataKeyPrefix = "KeePassHttp2_";

    private IPluginHost? _host;
    private WebSocketServer? _server;
    private Thread? _serverThread;
    private volatile bool _stopping;
    private volatile WebSocketConnection? _activeConnection;

    private byte[] _hostPublicKey = Array.Empty<byte>();
    private byte[] _hostSecretKey = Array.Empty<byte>();
    private readonly Dictionary<string, byte[]> _clientPublicKeys = new();
    private readonly NonceTracker _nonceTracker = new();

    public override bool Initialize(IPluginHost host)
    {
        PluginLog.WriteLine("Initialize() called");
        _host = host ?? throw new ArgumentNullException(nameof(host));

        try
        {
            (_hostPublicKey, _hostSecretKey) = NaClBox.GenerateKeyPair();
            PluginLog.WriteLine($"Host public key: {Convert.ToBase64String(_hostPublicKey)}");

            _server = new WebSocketServer();
            _server.Listen(ListenPort);
            PluginLog.WriteLine($"Listening on 127.0.0.1:{ListenPort}");

            _serverThread = new Thread(ServerLoop) { IsBackground = true, Name = "KeePassHttp2-Server" };
            _serverThread.Start();

            return true;
        }
        catch (Exception ex)
        {
            PluginLog.WriteLine($"Initialize FAILED: {ex}");
            return false;
        }
    }

    public override void Terminate()
    {
        _stopping = true;
        _server?.Shutdown();
        _activeConnection?.Dispose();
        _serverThread?.Join(TimeSpan.FromSeconds(2));
        _server?.Dispose();
    }

    private void ServerLoop()
    {
        using var rng = RandomNumberGenerator.Create();

        while (!_stopping)
        {
            PluginLog.WriteLine("Waiting for a connection...");
            var connection = _server!.Accept();
            if (_stopping) break;
            if (connection is null) continue; // shutdown race, or a rejected non-WebSocket request

            _activeConnection = connection;
            PluginLog.WriteLine("Connection accepted");

            while (!_stopping)
            {
                byte[]? raw = connection.Receive();
                if (raw is null)
                {
                    PluginLog.WriteLine("connection closed");
                    break;
                }

                string rawJson = Encoding.UTF8.GetString(raw);
                PluginLog.WriteLine($"received envelope: {rawJson}");

                try
                {
                    HandleEnvelope(connection, rawJson, rng);
                }
                catch (EnvelopeValidationException ex)
                {
                    PluginLog.WriteLine($"REJECTED: {ex.Message}");
                }
                catch (NaClBox.CryptoException ex)
                {
                    PluginLog.WriteLine($"CRYPTO ERROR: {ex.Message}");
                }
            }

            _activeConnection = null;
            connection.Dispose();
        }
    }

    private void HandleEnvelope(WebSocketConnection connection, string rawJson, RandomNumberGenerator rng)
    {
        var envelope = ProtocolEnvelopeParser.Parse(rawJson);
        var kind = ProtocolEnvelopeParser.Classify(envelope);

        if (kind == EnvelopeKind.ChangePublicKeys)
        {
            HandleChangePublicKeys(connection, envelope);
            return;
        }

        HandleEncrypted(connection, envelope, rng);
    }

    private void HandleChangePublicKeys(WebSocketConnection connection, ProtocolEnvelope envelope)
    {
        byte[] clientPk = ProtocolEnvelopeParser.DecodeFixedLength(
            envelope.PublicKey!, NaClBox.PublicKeyLength, "publicKey");

        _clientPublicKeys[envelope.ClientId!] = clientPk;
        PluginLog.WriteLine($"stored public key for clientID={envelope.ClientId}");

        string json = new JsonObjectWriter()
            .WriteString("action", "change-public-keys")
            .WriteString("publicKey", Convert.ToBase64String(_hostPublicKey))
            .WriteString("success", "true")
            .WriteString("version", ProtocolVersion)
            .Build();

        SendJson(connection, json);
    }

    private void HandleEncrypted(WebSocketConnection connection, ProtocolEnvelope envelope, RandomNumberGenerator rng)
    {
        if (!_clientPublicKeys.TryGetValue(envelope.ClientId!, out var clientPk))
            throw new EnvelopeValidationException($"unknown clientID: {envelope.ClientId}");

        if (_nonceTracker.IsReplay(envelope.ClientId!, envelope.Nonce!))
            throw new EnvelopeValidationException("nonce replay detected");

        byte[] nonce = ProtocolEnvelopeParser.DecodeFixedLength(envelope.Nonce!, NaClBox.NonceLength, "nonce");
        byte[] ciphertext = Convert.FromBase64String(envelope.Message!);

        byte[] plaintext = NaClBox.Open(ciphertext, nonce, clientPk, _hostSecretKey);
        _nonceTracker.Register(envelope.ClientId!, envelope.Nonce!);

        string innerJson = Encoding.UTF8.GetString(plaintext);
        NaClBox.SecureZero(plaintext);
        PluginLog.WriteLine($"decrypted inner: {innerJson}");

        var innerRoot = JsonParser.Parse(innerJson);
        var probe = InnerActionProbe.Parse(innerRoot);

        string innerResponseJson = probe.Action switch
        {
            "get-logins" => HandleGetLogins(innerRoot),
            "associate" => HandleAssociate(innerRoot, clientPk),
            "test-associate" => HandleTestAssociate(innerRoot),
            _ => throw new EnvelopeValidationException($"unhandled inner action: {probe.Action}"),
        };

        byte[] innerResponseBytes = Encoding.UTF8.GetBytes(innerResponseJson);

        byte[] responseNonce = new byte[NaClBox.NonceLength];
        rng.GetBytes(responseNonce);
        byte[] responseCiphertext = NaClBox.Seal(innerResponseBytes, responseNonce, clientPk, _hostSecretKey);
        NaClBox.SecureZero(innerResponseBytes);

        string outerJson = new JsonObjectWriter()
            .WriteString("action", probe.Action)
            .WriteString("message", Convert.ToBase64String(responseCiphertext))
            .WriteString("nonce", Convert.ToBase64String(responseNonce))
            .WriteString("clientID", envelope.ClientId)
            .Build();

        SendJson(connection, outerJson);
    }

    private static string FailureResponse() => new JsonObjectWriter()
        .WriteString("version", ProtocolVersion)
        .WriteString("success", "false")
        .Build();

    // The actual trust boundary for the whole protocol: pops up
    // AssociateDialog on the UI thread and blocks (this is a background
    // server thread, so blocking here is fine) until the human answers.
    // Stores the client's permanent identification public key in the open
    // database's CustomData, keyed by the name the human chose, and saves
    // immediately so the pairing survives a KeePass restart even if the
    // user never explicitly saves.
    private string HandleAssociate(JsonValue innerRoot, byte[] sessionClientPk)
    {
        var request = AssociateRequest.Parse(innerRoot);

        if (string.IsNullOrEmpty(request.Key) || string.IsNullOrEmpty(request.IdKey))
            throw new EnvelopeValidationException("associate: missing key/idKey");

        byte[] claimedSessionKey = ProtocolEnvelopeParser.DecodeFixedLength(
            request.Key, NaClBox.PublicKeyLength, "associate.key");
        if (!CryptoBytes.ConstantTimeEquals(claimedSessionKey, sessionClientPk))
            throw new EnvelopeValidationException("associate: key does not match current session");

        byte[] idKey = ProtocolEnvelopeParser.DecodeFixedLength(
            request.IdKey!, NaClBox.PublicKeyLength, "associate.idKey");

        PwDatabase? db = null;
        string? chosenName = null;

        _host!.MainWindow.Invoke(new MethodInvoker(() =>
        {
            db = _host.Database;
            if (db is null || !db.IsOpen) return;

            using var dialog = new AssociateDialog($"KeePassHttp2 client {DateTime.Now:HHmmss}");
            if (dialog.ShowDialog(_host.MainWindow) != DialogResult.OK) return;
            if (string.IsNullOrWhiteSpace(dialog.ChosenName)) return;

            chosenName = dialog.ChosenName;
            db.CustomData.Set(CustomDataKeyPrefix + chosenName, Convert.ToBase64String(idKey));
            db.Save(null);
        }));

        if (db is null || !db.IsOpen)
        {
            PluginLog.WriteLine("associate: no database open");
            return FailureResponse();
        }

        if (chosenName is null)
        {
            PluginLog.WriteLine("associate: user declined pairing");
            return FailureResponse();
        }

        PluginLog.WriteLine($"associate: paired as '{chosenName}'");

        return new JsonObjectWriter()
            .WriteString("hash", ComputeDatabaseHash(db))
            .WriteString("version", ProtocolVersion)
            .WriteString("success", "true")
            .WriteString("id", chosenName)
            .Build();
    }

    // Always returns a normal response (success: true/false) instead of
    // throwing - a client testing an association that no longer exists
    // (different database open, first connection ever, etc.) is an
    // expected, common case, not a protocol error.
    private string HandleTestAssociate(JsonValue innerRoot)
    {
        var request = TestAssociateRequest.Parse(innerRoot);

        if (string.IsNullOrEmpty(request.Id) || string.IsNullOrEmpty(request.Key))
            throw new EnvelopeValidationException("test-associate: missing id/key");

        byte[] claimedIdKey = ProtocolEnvelopeParser.DecodeFixedLength(
            request.Key, NaClBox.PublicKeyLength, "test-associate.key");

        PwDatabase? db = null;
        string? storedBase64 = null;

        _host!.MainWindow.Invoke(new MethodInvoker(() =>
        {
            db = _host.Database;
            if (db is null || !db.IsOpen) return;
            storedBase64 = db.CustomData.Get(CustomDataKeyPrefix + request.Id);
        }));

        bool success = false;
        if (db is not null && db.IsOpen && storedBase64 is not null)
        {
            byte[] storedIdKey = Convert.FromBase64String(storedBase64);
            success = storedIdKey.Length == claimedIdKey.Length &&
                       CryptoBytes.ConstantTimeEquals(storedIdKey, claimedIdKey);
        }

        PluginLog.WriteLine($"test-associate for id={request.Id}: {(success ? "known" : "unknown/mismatch")}");

        if (!success)
            return FailureResponse();

        return new JsonObjectWriter()
            .WriteString("version", ProtocolVersion)
            .WriteString("success", "true")
            .WriteString("hash", ComputeDatabaseHash(db!))
            .WriteString("id", request.Id)
            .Build();
    }

    // Runs on the background server thread. All PwDatabase/PwEntry access
    // is marshaled onto the UI thread via Invoke - db entries are read
    // into plain local values before Invoke returns, so nothing
    // KeePassLib-owned crosses back to this thread.
    private string HandleGetLogins(JsonValue innerRoot)
    {
        var request = GetLoginsRequest.Parse(innerRoot);
        PluginLog.WriteLine($"get-logins for url={request.Url}");

        var entryFragments = new List<string>();

        if (!string.IsNullOrEmpty(request.Url) && Uri.TryCreate(request.Url, UriKind.Absolute, out var requestUri))
        {
            _host!.MainWindow.Invoke(new MethodInvoker(() =>
            {
                PwDatabase? db = _host.Database;
                if (db is null || !db.IsOpen)
                {
                    PluginLog.WriteLine("get-logins: no database currently open");
                    return;
                }

                foreach (var entry in db.RootGroup.GetEntries(true))
                {
                    string entryUrl = entry.Strings.ReadSafe(PwDefs.UrlField);
                    if (string.IsNullOrEmpty(entryUrl)) continue;
                    if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var entryUri)) continue;
                    if (!string.Equals(entryUri.Host, requestUri.Host, StringComparison.OrdinalIgnoreCase)) continue;

                    string fragment = new JsonObjectWriter()
                        .WriteString("login", entry.Strings.ReadSafe(PwDefs.UserNameField))
                        .WriteString("password", entry.Strings.ReadSafe(PwDefs.PasswordField))
                        .WriteString("name", entry.Strings.ReadSafe(PwDefs.TitleField))
                        .WriteString("uuid", entry.Uuid.ToHexString())
                        .Build();
                    entryFragments.Add(fragment);
                }
            }));
        }

        var arrayWriter = new JsonArrayWriter();
        foreach (var fragment in entryFragments)
            arrayWriter.WriteRaw(fragment);
        string entriesJson = arrayWriter.Build();

        return new JsonObjectWriter()
            .WriteNumber("count", entryFragments.Count)
            .WriteRaw("entries", entriesJson)
            .WriteString("success", "true")
            .Build();
    }

    // Informational fingerprint of "which database is this" for the
    // client - stable across saves of the same database (root group UUID
    // doesn't change), changes if a different database is opened. Not a
    // security boundary, just a cache-invalidation hint (matches the
    // "hash" field's role in the real KeePassXC-Browser protocol).
    private static string ComputeDatabaseHash(PwDatabase db)
    {
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(db.RootGroup.Uuid.UuidBytes);
        return Convert.ToBase64String(hash);
    }

    private void SendJson(WebSocketConnection connection, string json)
    {
        PluginLog.WriteLine($"sending: {json}");
        connection.Send(Encoding.UTF8.GetBytes(json));
    }
}