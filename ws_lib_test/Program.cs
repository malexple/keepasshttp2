// WS transport smoke test: drives kp2_ws_listen/accept/recv/send/close from
// C#, echoing back whatever text the client sends. Point ws_test_client.py
// (or a browser) at ws://127.0.0.1:19455/ and compare behavior against the
// standalone ws_handshake.exe we already validated.
//
// Run: dotnet run

using System;
using System.Text;
using KeePassHttp2.Protocol;

NativeWebSocket.Listen(19455);
Console.WriteLine("Listening on 127.0.0.1:19455 (via Zig library)");

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
        byte[]? payload = NativeWebSocket.Recv(handle);
        if (payload is null)
        {
            Console.WriteLine("connection closed");
            break;
        }

        string text = Encoding.UTF8.GetString(payload);
        Console.WriteLine($"received: \"{text}\"");

        NativeWebSocket.Send(handle, payload);
        Console.WriteLine($"echoed back: \"{text}\"");
    }
}
