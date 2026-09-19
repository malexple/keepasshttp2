// P/Invoke wrapper for the WebSocket transport exports in keepass_crypto.zig.
// Draft/unverified until we run it against a real client (ws_test_client.py)
// and confirm the same handshake/echo/ping/close behavior we already proved
// out of the standalone ws_handshake.exe.

using System;
using System.Runtime.InteropServices;

namespace KeePassHttp2.Protocol;

public static class NativeWebSocket
{
    private const string LibraryName = "keepass_crypto";

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int kp2_ws_listen(ushort port);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void kp2_ws_shutdown();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int kp2_ws_accept();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe int kp2_ws_recv(int handle, byte* outBuf, nuint outBufLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe int kp2_ws_send(int handle, byte* buf, nuint bufLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void kp2_ws_close(int handle);

    public static void Listen(ushort port)
    {
        int result = kp2_ws_listen(port);
        if (result != 0)
            throw new InvalidOperationException($"kp2_ws_listen failed with code {result}");
    }

    public static void Shutdown() => kp2_ws_shutdown();

    public static int Accept() => kp2_ws_accept();

    // Returns null if the connection was closed (by peer, protocol error,
    // or oversized message), otherwise the decoded text payload bytes.
    public static byte[]? Recv(int handle, int maxSize = 8192)
    {
        var buf = new byte[maxSize];
        int n;
        unsafe
        {
            fixed (byte* p = buf)
            {
                n = kp2_ws_recv(handle, p, (nuint)buf.Length);
            }
        }
        if (n <= 0) return null;
        return buf[..n];
    }

    public static void Send(int handle, byte[] payload)
    {
        int result;
        unsafe
        {
            fixed (byte* p = payload)
            {
                result = kp2_ws_send(handle, p, (nuint)payload.Length);
            }
        }
        if (result != 0)
            throw new InvalidOperationException($"kp2_ws_send failed with code {result}");
    }

    public static void Close(int handle) => kp2_ws_close(handle);
}
