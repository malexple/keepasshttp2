// Minimal JSON value model. Deliberately not a general-purpose JSON
// library: no reflection, no attribute-driven type construction, no
// polymorphism. Untrusted input is parsed into this tree and every field
// we care about is read out explicitly by name and expected type -
// nothing else can be constructed from attacker-controlled JSON.

using System.Collections.Generic;

namespace KeePassHttp2.Json;

public enum JsonKind
{
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

public sealed class JsonValue
{
    public JsonKind Kind { get; }

    private readonly bool _bool;
    private readonly double _number;
    private readonly string? _string;
    private readonly List<JsonValue>? _array;
    private readonly Dictionary<string, JsonValue>? _object;

    private JsonValue(
        JsonKind kind,
        bool b = false,
        double n = 0,
        string? s = null,
        List<JsonValue>? a = null,
        Dictionary<string, JsonValue>? o = null)
    {
        Kind = kind;
        _bool = b;
        _number = n;
        _string = s;
        _array = a;
        _object = o;
    }

    public static readonly JsonValue Null = new(JsonKind.Null);
    public static JsonValue Of(bool b) => new(JsonKind.Bool, b: b);
    public static JsonValue Of(double n) => new(JsonKind.Number, n: n);
    public static JsonValue Of(string s) => new(JsonKind.String, s: s);
    public static JsonValue Of(List<JsonValue> a) => new(JsonKind.Array, a: a);
    public static JsonValue Of(Dictionary<string, JsonValue> o) => new(JsonKind.Object, o: o);

    public bool AsBool => Kind == JsonKind.Bool ? _bool : throw new JsonException("value is not a bool");
    public double AsNumber => Kind == JsonKind.Number ? _number : throw new JsonException("value is not a number");
    public string AsString => Kind == JsonKind.String ? _string! : throw new JsonException("value is not a string");
    public List<JsonValue> AsArray => Kind == JsonKind.Array ? _array! : throw new JsonException("value is not an array");
    public Dictionary<string, JsonValue> AsObject => Kind == JsonKind.Object ? _object! : throw new JsonException("value is not an object");

    private JsonValue? TryGet(string key) =>
        Kind == JsonKind.Object && _object!.TryGetValue(key, out var v) ? v : null;

    public bool HasKey(string key) => Kind == JsonKind.Object && _object!.ContainsKey(key);

    public IEnumerable<string> Keys => Kind == JsonKind.Object ? _object!.Keys : System.Array.Empty<string>();

    // Each accessor below distinguishes "field absent" (returns null) from
    // "field present but wrong type" (throws) - a type mismatch on
    // attacker-controlled input should be rejected outright, not silently
    // treated as if the field were missing.

    public string? TryGetString(string key)
    {
        var v = TryGet(key);
        if (v is null) return null;
        if (v.Kind != JsonKind.String)
            throw new JsonException($"field '{key}' must be a string");
        return v.AsString;
    }

    public bool? TryGetBool(string key)
    {
        var v = TryGet(key);
        if (v is null) return null;
        if (v.Kind != JsonKind.Bool)
            throw new JsonException($"field '{key}' must be a boolean");
        return v.AsBool;
    }

    public double? TryGetNumber(string key)
    {
        var v = TryGet(key);
        if (v is null) return null;
        if (v.Kind != JsonKind.Number)
            throw new JsonException($"field '{key}' must be a number");
        return v.AsNumber;
    }
}

public sealed class JsonException(string message) : System.Exception(message);