// Plugin-level settings (port, allowed WebSocket Origins), persisted as a
// small JSON file next to the plugin DLL - same location pattern as
// PluginLog. Deliberately NOT using IPluginHost.CustomConfig: its exact
// API wasn't something we could confirm with confidence from
// documentation alone, and getting a host API detail wrong means another
// build-break cycle. A self-contained file we fully control is simpler
// and just as reliable for something this small.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KeePassHttp2.Json;

namespace KeePassHttp2.Protocol;

internal static class PluginSettings
{
    public const ushort DefaultPort = 19455;

    private static readonly string ConfigPath = Path.Combine(
        Path.GetDirectoryName(typeof(PluginSettings).Assembly.Location) ?? ".",
        "keepasshttp2-settings.json");

    public static ushort Port { get; set; } = DefaultPort;

    // Empty = allow any Origin (today's behavior, unchanged unless the
    // user explicitly opts into an allow-list via the Options dialog).
    public static List<string> AllowedOrigins { get; set; } = new();

    public static void Load()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return;

            var root = JsonParser.Parse(File.ReadAllText(ConfigPath));

            var portValue = root.TryGetNumber("port");
            if (portValue.HasValue && portValue.Value > 0 && portValue.Value <= 65535)
                Port = (ushort)portValue.Value;

            string? origins = root.TryGetString("allowedOrigins");
            AllowedOrigins = ParseOrigins(origins);
        }
        catch
        {
            // Missing/corrupt settings file - fall back to defaults.
            // A settings file problem must never block plugin startup.
        }
    }

    public static void Save()
    {
        try
        {
            string json = new JsonObjectWriter()
                .WriteNumber("port", Port)
                .WriteString("allowedOrigins", string.Join(",", AllowedOrigins))
                .Build();
            File.WriteAllText(ConfigPath, json);
        }
        catch
        {
            // Best effort - a failed save shouldn't crash the Options dialog.
        }
    }

    public static List<string> ParseOrigins(string? commaSeparated) =>
        (commaSeparated ?? string.Empty)
            .Split(',')
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .ToList();
}