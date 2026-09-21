// KeePass.exe is a GUI app with no attached console, so Console.WriteLine
// is not a usable diagnostic channel once this code runs as a plugin.
// Everything that used to go to Console now goes to a log file sitting
// next to the plugin DLL instead.

using System;
using System.IO;

namespace KeePassHttp2.Protocol;

internal static class PluginLog
{
    private static readonly object Lock = new();

    private static readonly string LogPath = Path.Combine(
        Path.GetDirectoryName(typeof(PluginLog).Assembly.Location) ?? ".",
        "keepasshttp2.log");

    public static void WriteLine(string message)
    {
        lock (Lock)
        {
            try
            {
                File.AppendAllText(LogPath, $"{DateTime.Now:HH:mm:ss.fff} {message}{Environment.NewLine}");
            }
            catch
            {
                // Logging must never crash the plugin or the host.
            }
        }
    }
}