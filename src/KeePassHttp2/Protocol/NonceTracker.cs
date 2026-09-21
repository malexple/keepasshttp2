// Replay protection: per-clientID history of seen nonces.
//
// The real KeePassXC-Browser extension always sends a fully random 24-byte
// nonce with no timestamp field (see keepassxc-protocol.md: "nonce - 24
// bytes long random data"). So this is the universal, default mechanism for
// every client, not a fallback for clients lacking some optional field.
//
// Ordering contract (see NaClBox/ProtocolEnvelope callers):
//   1. Check IsReplay(clientId, nonce) BEFORE attempting decryption — a
//      cheap rejection of an exact repeated packet, and safe to do first
//      since the nonce travels in cleartext anyway (checking it first
//      leaks nothing an attacker replaying a captured packet doesn't
//      already know).
//   2. Only call Register(clientId, nonce) AFTER the message has been
//      successfully decrypted and authenticated (Box.open succeeded).
//      Registering before authentication would let an attacker "burn" a
//      nonce with garbage ciphertext and deny a legitimate client's retry
//      of that same request.

using System.Collections.Generic;

namespace KeePassHttp2.Protocol;

public sealed class NonceTracker
{
    // Cap per client: a local single-user password manager does not send
    // enough traffic to need unbounded history; a few thousand entries is
    // already a generous window while keeping memory bounded.
    private const int MaxNoncesPerClient = 4096;

    private sealed class ClientHistory
    {
        public readonly HashSet<string> Seen = new();
        public readonly Queue<string> Order = new();
    }

    private readonly Dictionary<string, ClientHistory> _byClient = new();
    private readonly object _lock = new();

    public bool IsReplay(string clientId, string nonceBase64)
    {
        lock (_lock)
        {
            return _byClient.TryGetValue(clientId, out var history) && history.Seen.Contains(nonceBase64);
        }
    }

    public void Register(string clientId, string nonceBase64)
    {
        lock (_lock)
        {
            if (!_byClient.TryGetValue(clientId, out var history))
            {
                history = new ClientHistory();
                _byClient[clientId] = history;
            }

            if (history.Seen.Add(nonceBase64))
            {
                history.Order.Enqueue(nonceBase64);
                while (history.Order.Count > MaxNoncesPerClient)
                {
                    var oldest = history.Order.Dequeue();
                    history.Seen.Remove(oldest);
                }
            }
        }
    }

    // Call when a client disassociates or the plugin wants to free memory
    // for a client that hasn't been seen in a long time.
    public void Forget(string clientId)
    {
        lock (_lock)
        {
            _byClient.Remove(clientId);
        }
    }
}