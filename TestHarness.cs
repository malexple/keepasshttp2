using System;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    private const string NativeLib = "keepasshttp2_native.dll";

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr RequestCallback(IntPtr data, UIntPtr len, out UIntPtr outLen);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    static extern int keepasshttp2_ping();

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    static extern void keepasshttp2_set_callback(RequestCallback cb);

    [DllImport(NativeLib, CallingConvention = CallingConvention.Cdecl)]
    static extern int keepasshttp2_invoke_test(byte[] msg, UIntPtr len);

    static RequestCallback callbackRef = null!;

    static IntPtr OnRequest(IntPtr data, UIntPtr len, out UIntPtr outLen)
    {
        var buf = new byte[(int)len];
        Marshal.Copy(data, buf, 0, (int)len);
        string text = Encoding.UTF8.GetString(buf);
        Console.WriteLine($"[C#] received from Zig: {text}");

        byte[] response = Encoding.UTF8.GetBytes("pong:" + text);
        IntPtr resultPtr = Marshal.AllocHGlobal(response.Length);
        Marshal.Copy(response, 0, resultPtr, response.Length);
        outLen = (UIntPtr)response.Length;
        return resultPtr; // leaked on purpose for this test - not production code
    }

    static void Main()
    {
        Console.WriteLine("ping() = " + keepasshttp2_ping()); // expect 42

        callbackRef = OnRequest;
        keepasshttp2_set_callback(callbackRef);

        byte[] msg = Encoding.UTF8.GetBytes("hello from csharp");
        int outLen = keepasshttp2_invoke_test(msg, (UIntPtr)msg.Length);
        Console.WriteLine("invoke_test returned outLen = " + outLen); // expect 21
    }
}