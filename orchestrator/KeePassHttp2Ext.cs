// Real KeePass plugin entry point. KeePass discovers this by scanning DLLs
// in its Plugins folder for a public class deriving from KeePass.Plugins.Plugin.
//
// Naming convention (required by KeePass, not optional): the assembly file
// name (without extension) must equal this class's namespace, and the
// class must be named "<Namespace>Ext". See orchestrator.csproj for the
// matching <AssemblyName>KeePassHttp2</AssemblyName> and <Product>KeePass
// Plugin</Product> settings - both are required for KeePass to even
// recognize this DLL as a plugin candidate.
//
// Lifecycle:
//   Initialize(host) - called by KeePass at startup/plugin load. Must
//     return quickly, so the WebSocket accept/recv loop runs on a
//     background thread, not here.
//   Terminate() - called at shutdown/plugin unload. Signals the loop to
//     stop and joins it with a timeout (best effort - see caveat below).
//
// Thread-safety: PwDatabase/PwEntry are not thread-safe and are owned by
// the UI thread. All access to host.Database is marshaled onto the UI
// thread via host.MainWindow.Invoke(...) from HandleGetLogins.
//
// Caveat (not yet verified): Terminate() calls NativeWebSocket.Shutdown()
// and joins the server thread with a timeout. Whether kp2_ws_shutdown
// actually unblocks a thread parked in kp2_ws_accept/kp2_ws_recv depends
// on the Zig implementation's shutdown semantics, which we have not
// inspected. If KeePass hangs on exit while a connection is open, this is
// the first place to look.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassHttp2.Protocol;
using KeePassLib;

namespace KeePassHttp2;

public sealed class KeePassHttp2Ext : Plugin
{
    private const ushort ListenPort = 19455;

    private IPluginHost? _host;
    private Thread? _serverThread;
    private volatile bool _stopping;

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
            (_hostPublicKey, _hostSecretKey) = NativeCrypto.GenerateKeyPair();
            PluginLog.WriteLine($"Host public key: {Convert.ToBase64String(_hostPublicKey)}");

            NativeWebSocket.Listen(ListenPort);
            PluginLog.WriteLine($"Listening on 127.0.0.1:{ListenPort} (orchestrator plugin)");

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
        NativeWebSocket.Shutdown();
        _serverThread?.Join(TimeSpan.FromSeconds(2));
    }

    private void ServerLoop()
    {
        using var rng = RandomNumberGenerator.Create();

        while (!_stopping)
        {
            PluginLog.WriteLine("Waiting for a connection...");
            int handle = NativeWebSocket.Accept();
            if (_stopping) break;
            if (handle < 0)
            {
                PluginLog.WriteLine($"accept failed/rejected: code {handle}");
                continue;
            }
            PluginLog.WriteLine($"Connection accepted, handle={handle}");

            while (!_stopping)
            {
                byte[]? raw = NativeWebSocket.Recv(handle);
                if (raw is null)
                {
                    PluginLog.WriteLine("connection closed");
                    break;
                }

                string rawJson = Encoding.UTF8.GetString(raw);
                PluginLog.WriteLine($"received envelope: {rawJson}");

                try
                {
                    HandleEnvelope(handle, rawJson, rng);
                }
                catch (EnvelopeValidationException ex)
                {
                    PluginLog.WriteLine($"REJECTED: {ex.Message}");
                }
                catch (NativeCrypto.CryptoException ex)
                {
                    PluginLog.WriteLine($"CRYPTO ERROR: {ex.Message}");
                }
            }
        }
    }

    private void HandleEnvelope(int handle, string rawJson, RandomNumberGenerator rng)
    {
        var envelope = ProtocolEnvelopeParser.Parse(rawJson);
        var kind = ProtocolEnvelopeParser.Classify(envelope);

        if (kind == EnvelopeKind.ChangePublicKeys)
        {
            HandleChangePublicKeys(handle, envelope);
            return;
        }

        HandleEncrypted(handle, envelope, rng);
    }

    private void HandleChangePublicKeys(int handle, ProtocolEnvelope envelope)
    {
        byte[] clientPk = ProtocolEnvelopeParser.DecodeFixedLength(
            envelope.PublicKey!, NativeCrypto.PublicKeyLength, "publicKey");

        _clientPublicKeys[envelope.ClientId!] = clientPk;
        PluginLog.WriteLine($"stored public key for clientID={envelope.ClientId}");

        var response = new
        {
            action = "change-public-keys",
            publicKey = Convert.ToBase64String(_hostPublicKey),
            success = "true",
            version = "2.0.0-stub",
        };

        SendJson(handle, response);
    }

    private void HandleEncrypted(int handle, ProtocolEnvelope envelope, RandomNumberGenerator rng)
    {
        if (!_clientPublicKeys.TryGetValue(envelope.ClientId!, out var clientPk))
            throw new EnvelopeValidationException($"unknown clientID: {envelope.ClientId}");

        if (_nonceTracker.IsReplay(envelope.ClientId!, envelope.Nonce!))
            throw new EnvelopeValidationException("nonce replay detected");

        byte[] nonce = ProtocolEnvelopeParser.DecodeFixedLength(envelope.Nonce!, NativeCrypto.NonceLength, "nonce");
        byte[] ciphertext = Convert.FromBase64String(envelope.Message!);

        byte[] plaintext = NativeCrypto.Open(ciphertext, nonce, clientPk, _hostSecretKey);
        _nonceTracker.Register(envelope.ClientId!, envelope.Nonce!);

        string innerJson = Encoding.UTF8.GetString(plaintext);
        NativeCrypto.SecureZero(plaintext);
        PluginLog.WriteLine($"decrypted inner: {innerJson}");

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
        byte[] responseCiphertext = NativeCrypto.Seal(innerResponseBytes, responseNonce, clientPk, _hostSecretKey);
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

    // Runs on the background server thread. All PwDatabase/PwEntry access
    // is marshaled onto the UI thread via Invoke - db entries are read
    // into plain anonymous objects (name/login/password/uuid strings)
    // before Invoke returns, so nothing KeePassLib-owned crosses back to
    // this thread.
    private object HandleGetLogins(string innerJson)
    {
        var request = JsonSerializer.Deserialize<GetLoginsRequest>(innerJson);
        PluginLog.WriteLine($"get-logins for url={request?.Url}");

        var matches = new List<object>();

        if (!string.IsNullOrEmpty(request?.Url) && Uri.TryCreate(request.Url, UriKind.Absolute, out var requestUri))
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

                    matches.Add(new
                    {
                        login = entry.Strings.ReadSafe(PwDefs.UserNameField),
                        password = entry.Strings.ReadSafe(PwDefs.PasswordField),
                        name = entry.Strings.ReadSafe(PwDefs.TitleField),
                        uuid = entry.Uuid.ToHexString(),
                    });
                }
            }));
        }

        return new
        {
            count = matches.Count,
            entries = matches,
            success = "true",
        };
    }

    private void SendJson(int handle, object payload)
    {
        string json = JsonSerializer.Serialize(payload);
        PluginLog.WriteLine($"sending: {json}");
        NativeWebSocket.Send(handle, Encoding.UTF8.GetBytes(json));
    }
}