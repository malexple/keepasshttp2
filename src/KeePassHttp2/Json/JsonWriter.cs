// Hand-rolled builders for our small set of fixed outgoing JSON shapes.
// No generic object-graph serialization - every outgoing message has a
// known shape, so we just write it directly with explicit escaping.

using System.Text;

namespace KeePassHttp2.Json;

public sealed class JsonObjectWriter
{
    private readonly StringBuilder _sb = new();
    private bool _first = true;

    public JsonObjectWriter() => _sb.Append('{');

    public JsonObjectWriter WriteString(string key, string? value)
    {
        WriteSeparatorAndKey(key);
        WriteJsonString(value);
        return this;
    }

    public JsonObjectWriter WriteNumber(string key, long value)
    {
        WriteSeparatorAndKey(key);
        _sb.Append(value);
        return this;
    }

    public JsonObjectWriter WriteBool(string key, bool value)
    {
        WriteSeparatorAndKey(key);
        _sb.Append(value ? "true" : "false");
        return this;
    }

    // For embedding an already-built JSON fragment (e.g. an array of
    // objects built with JsonArrayWriter) without re-escaping it.
    public JsonObjectWriter WriteRaw(string key, string rawJson)
    {
        WriteSeparatorAndKey(key);
        _sb.Append(rawJson);
        return this;
    }

    public string Build()
    {
        _sb.Append('}');
        return _sb.ToString();
    }

    private void WriteSeparatorAndKey(string key)
    {
        if (!_first) _sb.Append(',');
        _first = false;
        WriteJsonString(key);
        _sb.Append(':');
    }

    private void WriteJsonString(string? value)
    {
        if (value is null)
        {
            _sb.Append("null");
            return;
        }

        _sb.Append('"');
        foreach (char c in value)
        {
            switch (c)
            {
                case '"': _sb.Append("\\\""); break;
                case '\\': _sb.Append("\\\\"); break;
                case '\b': _sb.Append("\\b"); break;
                case '\f': _sb.Append("\\f"); break;
                case '\n': _sb.Append("\\n"); break;
                case '\r': _sb.Append("\\r"); break;
                case '\t': _sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                        _sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else
                        _sb.Append(c);
                    break;
            }
        }
        _sb.Append('"');
    }
}

public sealed class JsonArrayWriter
{
    private readonly StringBuilder _sb = new();
    private bool _first = true;

    public JsonArrayWriter() => _sb.Append('[');

    // Elements are always pre-built JSON fragments (typically from
    // JsonObjectWriter) - this writer only concatenates, it does not
    // escape, so callers must not pass raw unescaped strings here.
    public JsonArrayWriter WriteRaw(string rawJson)
    {
        if (!_first) _sb.Append(',');
        _first = false;
        _sb.Append(rawJson);
        return this;
    }

    public string Build()
    {
        _sb.Append(']');
        return _sb.ToString();
    }
}