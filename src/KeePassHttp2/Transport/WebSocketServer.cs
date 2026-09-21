// Pure managed WebSocket transport, replacing the old Zig/P/Invoke layer.
// HttpListener does the RFC6455 opening handshake and frame
// fragmentation/reassembly for us - we only deal with whole messages.
//
// API shape is deliberately synchronous/blocking (using
// GetAwaiter().GetResult() internally) rather than async, to match how
// the plugin's background server thread is structured: a plain blocking
// loop, not an async state machine. This is safe here specifically
// because this code always runs on a plain background Thread with no
// captured SynchronizationContext - blocking on a Task from such a
// thread cannot deadlock the way it can from a UI thread.
//
// Verified empirically (net48, dotnet test with a real ClientWebSocket):
// HttpListener.Start() on a loopback-only prefix (127.0.0.1 with a
// non-default port) does NOT require admin/urlacl on this environment -
// the earlier "Access is denied" risk did not materialize.

using System;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Threading;

namespace KeePassHttp2.Transport;

public sealed class WebSocketConnection : IDisposable
{
    private readonly WebSocket _socket;

    internal WebSocketConnection(WebSocket socket) => _socket = socket;

    // Returns null if the connection was closed (by peer or protocol
    // error), otherwise the full message payload (already reassembled
    // from any fragmented frames).
    public byte[]? Receive(int maxMessageSize = 65536)
    {
        var buffer = new byte[8192];
        using var ms = new MemoryStream();

        while (true)
        {
            WebSocketReceiveResult result;
            try
            {
                result = _socket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            catch (WebSocketException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }

            if (result.MessageType == WebSocketMessageType.Close)
            {
                // RFC6455 closing handshake: the peer sent its close
                // frame (WebSocket.State is now CloseReceived) - we must
                // send our own close frame back, otherwise the peer's
                // CloseAsync() blocks forever waiting for it.
                try
                {
                    _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None)
                        .GetAwaiter().GetResult();
                }
                catch
                {
                    // Best effort - peer may already have gone away.
                }
                return null;
            }

            ms.Write(buffer, 0, result.Count);
            if (ms.Length > maxMessageSize)
                return null; // oversized message, refuse rather than buffer unbounded

            if (result.EndOfMessage)
                return ms.ToArray();
        }
    }

    public void Send(byte[] payload)
    {
        _socket.SendAsync(
                new ArraySegment<byte>(payload),
                WebSocketMessageType.Text,
                endOfMessage: true,
                CancellationToken.None)
            .GetAwaiter().GetResult();
    }

    public void Close()
    {
        try
        {
            _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch
        {
            // Best effort - the peer may already be gone.
        }
    }

    public void Dispose() => _socket.Dispose();
}

public sealed class WebSocketServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private volatile bool _stopped;

    public void Listen(ushort port)
    {
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Start();
    }

    public void Shutdown()
    {
        _stopped = true;
        try
        {
            _listener.Stop();
        }
        catch
        {
            // Best effort.
        }
    }

    // Blocks until a client completes a WebSocket handshake, or returns
    // null if the listener was shut down, or the request was not a
    // WebSocket upgrade (in which case we respond 400 and keep waiting -
    // see caller's loop).
    public WebSocketConnection? Accept()
    {
        HttpListenerContext context;
        try
        {
            context = _listener.GetContextAsync().GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            if (_stopped) return null;
            throw;
        }

        if (!context.Request.IsWebSocketRequest)
        {
            context.Response.StatusCode = 400;
            context.Response.Close();
            return null;
        }

        HttpListenerWebSocketContext wsContext;
        try
        {
            wsContext = context.AcceptWebSocketAsync(subProtocol: null).GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            context.Response.StatusCode = 500;
            context.Response.Close();
            return null;
        }

        return new WebSocketConnection(wsContext.WebSocket);
    }

    public void Dispose() => _listener.Close();
}