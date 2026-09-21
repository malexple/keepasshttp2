// Strict recursive-descent JSON parser for untrusted input. Rejects
// trailing garbage, unescaped control characters in strings, malformed
// numbers/escapes, and nesting beyond maxDepth - the last one matters
// because our protocol's envelope and inner messages are always flat
// objects; anything nesting deeper than expected is already suspicious.
//
// Depth semantics: the top-level container is depth 1. Any container
// (object/array) nested one level inside a field of that top container is
// depth 2, and so on. With the default maxDepth=2, a flat object/array of
// scalars is allowed, but a field whose value is itself an object/array
// is rejected - matching the shape of our protocol's envelopes and inner
// messages exactly.

using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace KeePassHttp2.Json;

public static class JsonParser
{
    public const int DefaultMaxDepth = 2;

    public static JsonValue Parse(string json, int maxDepth = DefaultMaxDepth)
    {
        int pos = 0;
        var value = ParseValue(json, ref pos, 1, maxDepth);
        SkipWhitespace(json, ref pos);
        if (pos != json.Length)
            throw new JsonException($"unexpected trailing content at position {pos}");
        return value;
    }

    private static JsonValue ParseValue(string s, ref int pos, int depth, int maxDepth)
    {
        SkipWhitespace(s, ref pos);
        if (pos >= s.Length)
            throw new JsonException("unexpected end of input");

        return s[pos] switch
        {
            '{' => ParseObject(s, ref pos, depth, maxDepth),
            '[' => ParseArray(s, ref pos, depth, maxDepth),
            '"' => JsonValue.Of(ParseString(s, ref pos)),
            't' => ParseLiteral(s, ref pos, "true", JsonValue.Of(true)),
            'f' => ParseLiteral(s, ref pos, "false", JsonValue.Of(false)),
            'n' => ParseLiteral(s, ref pos, "null", JsonValue.Null),
            _ => ParseNumber(s, ref pos),
        };
    }

    private static JsonValue ParseObject(string s, ref int pos, int depth, int maxDepth)
    {
        if (depth >= maxDepth)
            throw new JsonException("maximum nesting depth exceeded");

        pos++; // '{'
        var result = new Dictionary<string, JsonValue>();
        SkipWhitespace(s, ref pos);
        if (Peek(s, pos) == '}')
        {
            pos++;
            return JsonValue.Of(result);
        }

        while (true)
        {
            SkipWhitespace(s, ref pos);
            if (Peek(s, pos) != '"')
                throw new JsonException($"expected string key at position {pos}");
            string key = ParseString(s, ref pos);
            SkipWhitespace(s, ref pos);
            if (Peek(s, pos) != ':')
                throw new JsonException($"expected ':' at position {pos}");
            pos++;
            var value = ParseValue(s, ref pos, depth + 1, maxDepth);
            result[key] = value;
            SkipWhitespace(s, ref pos);
            char c = Peek(s, pos);
            if (c == ',') { pos++; continue; }
            if (c == '}') { pos++; break; }
            throw new JsonException($"expected ',' or '}}' at position {pos}");
        }
        return JsonValue.Of(result);
    }

    private static JsonValue ParseArray(string s, ref int pos, int depth, int maxDepth)
    {
        if (depth >= maxDepth)
            throw new JsonException("maximum nesting depth exceeded");

        pos++; // '['
        var result = new List<JsonValue>();
        SkipWhitespace(s, ref pos);
        if (Peek(s, pos) == ']')
        {
            pos++;
            return JsonValue.Of(result);
        }

        while (true)
        {
            var value = ParseValue(s, ref pos, depth + 1, maxDepth);
            result.Add(value);
            SkipWhitespace(s, ref pos);
            char c = Peek(s, pos);
            if (c == ',') { pos++; continue; }
            if (c == ']') { pos++; break; }
            throw new JsonException($"expected ',' or ']' at position {pos}");
        }
        return JsonValue.Of(result);
    }

    private static string ParseString(string s, ref int pos)
    {
        pos++; // opening quote
        var sb = new StringBuilder();
        while (true)
        {
            if (pos >= s.Length)
                throw new JsonException("unterminated string");
            char c = s[pos++];
            if (c == '"')
                break;

            if (c == '\\')
            {
                if (pos >= s.Length)
                    throw new JsonException("unterminated escape sequence");
                char esc = s[pos++];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (pos + 4 > s.Length)
                            throw new JsonException("invalid unicode escape");
                        string hex = s.Substring(pos, 4);
                        if (!ushort.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort code))
                            throw new JsonException("invalid unicode escape");
                        sb.Append((char)code);
                        pos += 4;
                        break;
                    default:
                        throw new JsonException($"invalid escape character '\\{esc}'");
                }
            }
            else if (c < 0x20)
            {
                throw new JsonException("unescaped control character in string");
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    private static JsonValue ParseNumber(string s, ref int pos)
    {
        int start = pos;
        if (Peek(s, pos) == '-') pos++;
        if (pos >= s.Length || !IsAsciiDigit(s[pos]))
            throw new JsonException($"invalid number at position {start}");
        while (pos < s.Length && IsAsciiDigit(s[pos])) pos++;

        if (Peek(s, pos) == '.')
        {
            pos++;
            if (pos >= s.Length || !IsAsciiDigit(s[pos]))
                throw new JsonException("invalid number: expected digit after '.'");
            while (pos < s.Length && IsAsciiDigit(s[pos])) pos++;
        }

        if (Peek(s, pos) is 'e' or 'E')
        {
            pos++;
            if (Peek(s, pos) is '+' or '-') pos++;
            if (pos >= s.Length || !IsAsciiDigit(s[pos]))
                throw new JsonException("invalid number: expected digit in exponent");
            while (pos < s.Length && IsAsciiDigit(s[pos])) pos++;
        }

        string numberText = s.Substring(start, pos - start);
        if (!double.TryParse(numberText, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            throw new JsonException($"invalid number '{numberText}'");
        return JsonValue.Of(value);
    }

    private static JsonValue ParseLiteral(string s, ref int pos, string literal, JsonValue value)
    {
        if (pos + literal.Length > s.Length || s.Substring(pos, literal.Length) != literal)
            throw new JsonException($"expected '{literal}' at position {pos}");
        pos += literal.Length;
        return value;
    }

    // Deliberately not char.IsDigit: that also matches non-ASCII Unicode
    // digits, which strict JSON numbers must never accept. Also not
    // char.IsAsciiDigit: that's a .NET 7+ API, unavailable on net48.
    private static bool IsAsciiDigit(char c) => c >= '0' && c <= '9';

    private static char Peek(string s, int pos) => pos < s.Length ? s[pos] : '\0';

    private static void SkipWhitespace(string s, ref int pos)
    {
        while (pos < s.Length && (s[pos] is ' ' or '\t' or '\n' or '\r'))
            pos++;
    }
}