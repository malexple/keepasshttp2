// End-to-end tests against a real HttpListener-backed WebSocketServer,
// using the in-box ClientWebSocket as a genuine RFC6455 client - not a
// mock. If WebSocketServer.Listen() throws HttpListenerException here,
// that's the "Access is denied" risk flagged in WebSocketServer.cs
// surfacing - see that file's header for the fallback plan.
//
// Note: ClientWebSocket.CloseAsync() waits for the peer's close reply
// before returning, so any test using it must have the server side
// already actively calling Receive() (which is what sends that reply) -
// otherwise both sides deadlock waiting on each other. Where we only
// need to send a close frame without waiting for the round trip, use
// CloseOutputAsync() instead.

using System;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeePassHttp2.Transport;
using Xunit;

namespace KeePassHttp2.Tests;

public class TransportTests
{
    [Fact]
    public async Task Server_HandshakeAndEcho_RoundTrips()
    {
        const ushort port = 19951;
        using var server = new WebSocketServer();
        server.Listen(port);

        var acceptTask = Task.Run(() => server.Accept());

        using var client = new ClientWebSocket();
        await client.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/"), CancellationToken.None);

        var connection = await acceptTask;
        Assert.NotNull(connection);

        var sent = Encoding.UTF8.GetBytes("hello from client");
        await client.SendAsync(new ArraySegment<byte>(sent), WebSocketMessageType.Text, true, CancellationToken.None);

        var received = connection!.Receive();
        Assert.NotNull(received);
        Assert.Equal("hello from client", Encoding.UTF8.GetString(received!));

        connection.Send(Encoding.UTF8.GetBytes("hello from server"));

        var clientBuffer = new byte[8192];
        var result = await client.ReceiveAsync(new ArraySegment<byte>(clientBuffer), CancellationToken.None);
        Assert.Equal("hello from server", Encoding.UTF8.GetString(clientBuffer, 0, result.Count));

        server.Shutdown();
    }

    [Fact]
    public async Task Server_ClientCloses_ReceiveReturnsNull()
    {
        const ushort port = 19952;
        using var server = new WebSocketServer();
        server.Listen(port);

        var acceptTask = Task.Run(() => server.Accept());

        using var client = new ClientWebSocket();
        await client.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/"), CancellationToken.None);
        var connection = await acceptTask;
        Assert.NotNull(connection);

        // Fire-and-forget close frame - do not wait for the server's
        // reply here, since the server only sends it once Receive() (on
        // the next line) actually processes the incoming close.
        await client.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);

        var received = connection!.Receive();
        Assert.Null(received);

        server.Shutdown();
    }

    [Fact]
    public void Shutdown_UnblocksPendingAccept()
    {
        const ushort port = 19953;
        var server = new WebSocketServer();
        server.Listen(port);

        var acceptTask = Task.Run(() => server.Accept());

        // Give Accept() a moment to actually start blocking inside
        // GetContextAsync before we shut down, so this genuinely tests
        // unblocking a pending call rather than a race at startup.
        Thread.Sleep(200);
        server.Shutdown();

        bool completed = acceptTask.Wait(TimeSpan.FromSeconds(5));
        Assert.True(completed, "Accept() did not unblock within 5 seconds of Shutdown()");
        Assert.Null(acceptTask.Result);
    }

    [Fact]
    public async Task Server_RejectsDisallowedOrigin()
    {
        const ushort port = 19954;
        using var server = new WebSocketServer();
        server.Listen(port);

        var acceptTask = Task.Run(() => server.Accept(origin => origin == "https://allowed.example"));

        using var client = new ClientWebSocket();
        client.Options.SetRequestHeader("Origin", "https://not-allowed.example");

        // A rejected handshake surfaces to the client as a failed
        // ConnectAsync (403 instead of the expected 101 upgrade), not as
        // a connection that opens and then gets closed.
        await Assert.ThrowsAsync<WebSocketException>(
            () => client.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/"), CancellationToken.None));

        var connection = await acceptTask;
        Assert.Null(connection);

        server.Shutdown();
    }

    [Fact]
    public async Task Server_AllowsMatchingOrigin()
    {
        const ushort port = 19955;
        using var server = new WebSocketServer();
        server.Listen(port);

        var acceptTask = Task.Run(() => server.Accept(origin => origin == "https://allowed.example"));

        using var client = new ClientWebSocket();
        client.Options.SetRequestHeader("Origin", "https://allowed.example");
        await client.ConnectAsync(new Uri($"ws://127.0.0.1:{port}/"), CancellationToken.None);

        var connection = await acceptTask;
        Assert.NotNull(connection);

        server.Shutdown();
    }
}