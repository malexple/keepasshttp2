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
// thread via host.MainWindow.Invoke(...) from HandleGetLogins.
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

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassHttp2.Crypto;
using KeePassHttp2.Json;
using KeePassHttp2.Protocol;
using KeePassHttp2.Transport;
using KeePassLib;

namespace KeePassHttp2;

public sealed class KeePassHttp2Ext : Plugin
{
    private const ushort ListenPort = 19455;

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
            .WriteString("version", "2.0.0-stub")
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

    private void SendJson(WebSocketConnection connection, string json)
    {
        PluginLog.WriteLine($"sending: {json}");
        connection.Send(Encoding.UTF8.GetBytes(json));
    }
}