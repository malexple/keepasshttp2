// Real KeePass plugin entry point. KeePass discovers this by scanning DLLs
// in its Plugins folder for a public class deriving from KeePass.Plugins.Plugin.
//
// Naming convention (required by KeePass, not optional): the assembly file
// name (without extension) must equal this class's namespace, and the
// class must be named "<Namespace>Ext". KeePassHttp2.csproj's
// <AssemblyName> must match this - see that file.
//
// Lifecycle:
//   Initialize(host) - called by KeePass at startup/plugin load. Must
//     return quickly, so the WebSocket accept/recv loop runs on a
//     background thread, not here.
//   Terminate() - called at shutdown/plugin unload. Signals the loop to
//     stop, disposes any in-flight connection, and joins the thread with
//     a timeout.
//   GetMenuItem(PluginMenuType.Main) - adds "KeePassHttp2 Options..." to
//     the Tools menu (the officially documented way plugins add UI entry
//     points - see keepass.info/help/v2_dev/plg_index.html).
//
// Thread-safety: PwDatabase/PwEntry are not thread-safe and are owned by
// the UI thread. All access to host.Database is marshaled onto the UI
// thread via host.MainWindow.Invoke(...).
//
// Crash containment: ServerLoop's per-message try/catch includes a
// catch-all for Exception, not just our own expected exception types. An
// unhandled exception on a background Thread (not a ThreadPool task)
// takes down the entire process in .NET - so any bug in message handling
// would otherwise crash the whole KeePass process, not just this plugin.
//
// Logging policy: keepasshttp2.log intentionally logs very little - see
// PluginSettings.cs / the log call sites below for what's deliberately
// excluded (URLs, full payloads, full clientIDs) and what's kept on
// purpose (the associate/test-associate audit trail). "reject-conn"
// covers handshakes HttpListener/WebSocketServer refused outright (bad
// request, disallowed Origin, or a brief race during a port switch via
// the Options dialog) - previously these left no trace at all, which
// made a real port-switch race impossible to diagnose from the log.
//
// Settings: port and allowed-Origins are persisted via PluginSettings
// (a small JSON file next to the DLL), not IPluginHost.CustomConfig - see
// PluginSettings.cs for why.
//
// Trust model (change-public-keys / associate / test-associate):
// change-public-keys is free for anyone to call - it's just an ephemeral
// key exchange, no secrets. associate is the actual trust boundary: it
// pops up AssociateDialog on the KeePass UI thread, and nothing proceeds
// until a human clicks Allow. Once allowed, the client's permanent
// identification public key is stored in the open database's CustomData
// (survives KeePass restarts), and test-associate on a later connection
// just looks it up and compares - this matches how KeePassXC-Browser
// itself does it, including its known limitation that test-associate is
// a plain key comparison, not a fresh challenge-response proof of
// possession (see README - accepted, documented risk, not an oversight).
// The optional Origin allow-list (see WebSocketServer.Accept) is a
// separate, weaker layer: it only ever stops a real browser connecting
// from an unexpected page, not an arbitrary local process, which can set
// Origin to anything.

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
        PluginLog.WriteLine("init");
        _host = host ?? throw new ArgumentNullException(nameof(host));

        try
        {
            PluginSettings.Load();
            (_hostPublicKey, _hostSecretKey) = NaClBox.GenerateKeyPair();
            StartServer();
            return true;
        }
        catch (Exception ex)
        {
            PluginLog.WriteLine($"init-failed: {ex.GetType().Name}");
            return false;
        }
    }

    public override void Terminate()
    {
        StopServer();
    }

    public override ToolStripMenuItem? GetMenuItem(PluginMenuType t)
    {
        if (t != PluginMenuType.Main) return null;

        var menuItem = new ToolStripMenuItem { Text = "KeePassHttp2 Options..." };
        menuItem.Click += (_, _) => ShowOptionsDialog();
        return menuItem;
    }

    private void ShowOptionsDialog()
    {
        using var dialog = new OptionsDialog(PluginSettings.Port, string.Join(",", PluginSettings.AllowedOrigins));
        if (dialog.ShowDialog(_host!.MainWindow) != DialogResult.OK) return;

        bool portChanged = dialog.Port != PluginSettings.Port;
        PluginSettings.Port = dialog.Port;
        PluginSettings.AllowedOrigins = PluginSettings.ParseOrigins(dialog.AllowedOrigins);
        PluginSettings.Save();

        if (portChanged)
        {
            StopServer();
            _stopping = false;
            StartServer();
        }
    }

    private void StartServer()
    {
        _server = new WebSocketServer();
        _server.Listen(PluginSettings.Port);
        PluginLog.WriteLine($"listening :{PluginSettings.Port}");

        _serverThread = new Thread(ServerLoop) { IsBackground = true, Name = "KeePassHttp2-Server" };
        _serverThread.Start();
    }

    private void StopServer()
    {
        _stopping = true;
        _server?.Shutdown();
        _activeConnection?.Dispose();
        _serverThread?.Join(TimeSpan.FromSeconds(2));
        _server?.Dispose();
    }

    private bool IsOriginAllowed(string? origin)
    {
        if (PluginSettings.AllowedOrigins.Count == 0) return true;
        return origin is not null && PluginSettings.AllowedOrigins.Contains(origin);
    }

    private void ServerLoop()
    {
        using var rng = RandomNumberGenerator.Create();

        while (!_stopping)
        {
            var connection = _server!.Accept(IsOriginAllowed);
            if (_stopping) break;
            if (connection is null)
            {
                // Bad request, disallowed Origin, or a race during a
                // port switch (see file header) - previously silent,
                // now at least a breadcrumb in the log.
                PluginLog.WriteLine("reject-conn");
                continue;
            }

            _activeConnection = connection;
            PluginLog.WriteLine("accept");

            while (!_stopping)
            {
                byte[]? raw = connection.Receive();
                if (raw is null)
                {
                    PluginLog.WriteLine("close");
                    break;
                }

                try
                {
                    HandleEnvelope(connection, Encoding.UTF8.GetString(raw), rng);
                }
                catch (EnvelopeValidationException ex)
                {
                    PluginLog.WriteLine($"reject: {ex.Message}");
                }
                catch (NaClBox.CryptoException ex)
                {
                    PluginLog.WriteLine($"crypto-error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Catch-all so a bug in one message can't crash the
                    // whole KeePass process - see file header. Type name
                    // only, no message/stack trace: those can embed
                    // request data.
                    PluginLog.WriteLine($"unexpected-error: {ex.GetType().Name}");
                }
            }

            _activeConnection = null;
            connection.Dispose();
        }
    }

    // First 8 chars only - enough to tell "same client across two log
    // lines" apart from "different client", without writing the full
    // clientID (a random per-session value, low sensitivity, but no
    // reason to write more of it than we need to).
    private static string ShortId(string clientId) =>
        clientId.Length <= 8 ? clientId : clientId.Substring(0, 8);

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
        PluginLog.WriteLine($"change-public-keys client={ShortId(envelope.ClientId!)}");

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
            throw new EnvelopeValidationException($"unknown clientID: {ShortId(envelope.ClientId!)}");

        if (_nonceTracker.IsReplay(envelope.ClientId!, envelope.Nonce!))
            throw new EnvelopeValidationException("nonce replay detected");

        byte[] nonce = ProtocolEnvelopeParser.DecodeFixedLength(envelope.Nonce!, NaClBox.NonceLength, "nonce");
        byte[] ciphertext = Convert.FromBase64String(envelope.Message!);

        byte[] plaintext = NaClBox.Open(ciphertext, nonce, clientPk, _hostSecretKey);
        _nonceTracker.Register(envelope.ClientId!, envelope.Nonce!);

        string innerJson = Encoding.UTF8.GetString(plaintext);
        NaClBox.SecureZero(plaintext);

        var innerRoot = JsonParser.Parse(innerJson);
        var probe = InnerActionProbe.Parse(innerRoot);
        PluginLog.WriteLine($"{probe.Action} client={ShortId(envelope.ClientId!)}");

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
            PluginLog.WriteLine("associate: no db open");
            return FailureResponse();
        }

        if (chosenName is null)
        {
            PluginLog.WriteLine("associate: declined");
            return FailureResponse();
        }

        // Deliberate audit log, not incidental leakage - see file header.
        PluginLog.WriteLine($"associate: paired '{chosenName}'");

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
    // Always returns a normal response (success: true/false) instead of
    // throwing - a client testing an association that no longer exists
    // (different database open, first connection ever, etc.) is an
    // expected, common case, not a protocol error. An empty/missing "id" in
    // particular is the standard first-connection case (the client has no
    // saved association yet and is proactively checking before calling
    // associate) - only a missing "key" is an actual malformed request.
    private string HandleTestAssociate(JsonValue innerRoot)
    {
        var request = TestAssociateRequest.Parse(innerRoot);

        if (string.IsNullOrEmpty(request.Key))
            throw new EnvelopeValidationException("test-associate: missing key");

        if (string.IsNullOrEmpty(request.Id))
        {
            PluginLog.WriteLine("test-associate '': unknown (no prior association)");
            return FailureResponse();
        }

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

        // Deliberate audit log, not incidental leakage - see file header.
        PluginLog.WriteLine($"test-associate '{request.Id}': {(success ? "ok" : "unknown")}");

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
        var entryFragments = new List<string>();

        if (!string.IsNullOrEmpty(request.Url) && Uri.TryCreate(request.Url, UriKind.Absolute, out var requestUri))
        {
            _host!.MainWindow.Invoke(new MethodInvoker(() =>
            {
                PwDatabase? db = _host.Database;
                if (db is null || !db.IsOpen) return;

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

        // Intentionally not logging request.Url or match count here -
        // that's browsing history, not something this log file should
        // ever contain. See file header.

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
        connection.Send(Encoding.UTF8.GetBytes(json));
    }
}