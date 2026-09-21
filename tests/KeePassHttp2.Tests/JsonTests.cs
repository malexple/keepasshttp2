using KeePassHttp2.Json;
using KeePassHttp2.Protocol;
using Xunit;

namespace KeePassHttp2.Tests;

public class JsonParserTests
{
    [Fact]
    public void ParsesFlatObjectWithAllScalarTypes()
    {
        var root = JsonParser.Parse("""{"a":"text","b":42,"c":true,"d":false,"e":null}""");
        Assert.Equal(JsonKind.Object, root.Kind);
        Assert.Equal("text", root.TryGetString("a"));
        Assert.Equal(42, root.TryGetNumber("b"));
        Assert.True(root.TryGetBool("c"));
        Assert.False(root.TryGetBool("d"));
        Assert.True(root.HasKey("e"));
    }

    [Fact]
    public void ParsesEscapedStringCorrectly()
    {
        var root = JsonParser.Parse("""{"s":"line1\nline2\t\"quoted\"\\backslash"}""");
        Assert.Equal("line1\nline2\t\"quoted\"\\backslash", root.TryGetString("s"));
    }

    [Fact]
    public void ParsesUnicodeEscape()
    {
        var root = JsonParser.Parse("""{"s":"\u002B"}""");
        Assert.Equal("+", root.TryGetString("s"));
    }

    [Fact]
    public void RejectsTrailingGarbage()
    {
        Assert.Throws<JsonException>(() => JsonParser.Parse("{}garbage"));
    }

    [Fact]
    public void RejectsUnescapedControlCharacterInString()
    {
        string withRawNewline = "{\"s\":\"a\nb\"}";
        Assert.Throws<JsonException>(() => JsonParser.Parse(withRawNewline));
    }

    [Fact]
    public void RejectsNestingBeyondMaxDepth()
    {
        // Envelope/inner messages are always flat objects (maxDepth=2), so
        // a field whose value is itself an object must be rejected.
        Assert.Throws<JsonException>(() => JsonParser.Parse("""{"a":{"b":1}}""", maxDepth: 2));
    }

    [Fact]
    public void AllowsFlatObjectAtMaxDepth()
    {
        var root = JsonParser.Parse("""{"a":1}""", maxDepth: 2);
        Assert.Equal(1, root.TryGetNumber("a"));
    }

    [Fact]
    public void TryGetString_WrongType_Throws()
    {
        var root = JsonParser.Parse("""{"a":42}""");
        Assert.Throws<JsonException>(() => root.TryGetString("a"));
    }

    [Fact]
    public void TryGetString_MissingField_ReturnsNull()
    {
        var root = JsonParser.Parse("""{}""");
        Assert.Null(root.TryGetString("missing"));
    }
}

public class JsonWriterTests
{
    [Fact]
    public void ObjectWriter_EscapesSpecialCharacters()
    {
        string json = new JsonObjectWriter()
            .WriteString("s", "quote\"backslash\\newline\ntab\t")
            .Build();

        var parsed = JsonParser.Parse(json);
        Assert.Equal("quote\"backslash\\newline\ntab\t", parsed.TryGetString("s"));
    }

    [Fact]
    public void ObjectWriter_RoundTripsThroughParser()
    {
        string json = new JsonObjectWriter()
            .WriteString("action", "get-logins")
            .WriteNumber("count", 2)
            .WriteBool("success", true)
            .Build();

        var parsed = JsonParser.Parse(json);
        Assert.Equal("get-logins", parsed.TryGetString("action"));
        Assert.Equal(2, parsed.TryGetNumber("count"));
        Assert.True(parsed.TryGetBool("success"));
    }

    [Fact]
    public void ArrayWriter_OfObjects_RoundTripsThroughParser()
    {
        // This shape (object -> array -> objects) is 3 levels deep,
        // deeper than the strict maxDepth=2 used for protocol envelopes -
        // that limit is a ProtocolEnvelopeParser policy, not a general
        // limitation of JsonParser itself, so we raise it explicitly here.
        string entry1 = new JsonObjectWriter().WriteString("login", "alice").Build();
        string entry2 = new JsonObjectWriter().WriteString("login", "bob").Build();
        string arrayJson = new JsonArrayWriter().WriteRaw(entry1).WriteRaw(entry2).Build();
        string outer = new JsonObjectWriter().WriteRaw("entries", arrayJson).Build();

        var parsed = JsonParser.Parse(outer, maxDepth: 4);
        var entries = parsed.AsObject["entries"].AsArray;
        Assert.Equal(2, entries.Count);
        Assert.Equal("alice", entries[0].TryGetString("login"));
        Assert.Equal("bob", entries[1].TryGetString("login"));
    }
}

public class ProtocolEnvelopeParserTests
{
    // These three strings are real traffic captured from earlier manual
    // end-to-end test runs against the orchestrator (see conversation
    // history) - not synthetic examples.

    private const string RealChangePublicKeysEnvelope =
        """{"action": "change-public-keys", "publicKey": "g45lF0AToMheV4P4FsyJwxYSFyxlYgSGVlWzhrtmfRA=", "nonce": "cL7LZ9f4frj2QH+xJW/JdvVHdMH5x+Sg", "clientID": "kvTZCMX6aRqV781OMeKJig=="}""";

    private const string RealGetLoginsEnvelope =
        """{"action": "get-logins", "message": "IJTgODyC2Lioow4K0Hgsmc495U256nJqUzW2s3NX9pMXaKucIxR+GpIk2/68TNFykU2T9fGOiGlE0lazYl2efk5JF9eqlS33H04HT5zbqCH8SUv4Jg4kb9ZZM7cfj9pN++uwRm2iCuxSsB5cbn5SVA==", "nonce": "4nAK7bkNBVUH6CatqOded0AmdKTMShcc", "clientID": "kvTZCMX6aRqV781OMeKJig=="}""";

    private const string RealInnerGetLoginsMessage =
        """{"action": "get-logins", "url": "https://example.com", "submitUrl": "https://example.com/login"}""";

    [Fact]
    public void ParsesRealChangePublicKeysEnvelope()
    {
        var envelope = ProtocolEnvelopeParser.Parse(RealChangePublicKeysEnvelope);
        Assert.Equal("change-public-keys", envelope.Action);
        Assert.Equal("kvTZCMX6aRqV781OMeKJig==", envelope.ClientId);
        Assert.Equal("cL7LZ9f4frj2QH+xJW/JdvVHdMH5x+Sg", envelope.Nonce);
        Assert.Equal("g45lF0AToMheV4P4FsyJwxYSFyxlYgSGVlWzhrtmfRA=", envelope.PublicKey);
        Assert.Equal(EnvelopeKind.ChangePublicKeys, ProtocolEnvelopeParser.Classify(envelope));
    }

    [Fact]
    public void ParsesRealEncryptedGetLoginsEnvelope()
    {
        var envelope = ProtocolEnvelopeParser.Parse(RealGetLoginsEnvelope);
        Assert.Equal("get-logins", envelope.Action);
        Assert.Equal("kvTZCMX6aRqV781OMeKJig==", envelope.ClientId);
        Assert.StartsWith("IJTgODyC2Lioow4K0Hgsmc", envelope.Message);
        Assert.Equal(EnvelopeKind.Encrypted, ProtocolEnvelopeParser.Classify(envelope));
    }

    [Fact]
    public void ParsesRealInnerGetLoginsMessage()
    {
        var root = JsonParser.Parse(RealInnerGetLoginsMessage);
        var probe = InnerActionProbe.Parse(root);
        var request = GetLoginsRequest.Parse(root);

        Assert.Equal("get-logins", probe.Action);
        Assert.Equal("https://example.com", request.Url);
        Assert.Equal("https://example.com/login", request.SubmitUrl);
    }

    [Fact]
    public void RejectsUnknownField()
    {
        string withExtraField = """{"action":"get-logins","message":"AAAA","nonce":"BBBB","clientID":"CCCC","evilField":"x"}""";
        Assert.Throws<EnvelopeValidationException>(() => ProtocolEnvelopeParser.Parse(withExtraField));
    }

    [Fact]
    public void RejectsUnknownAction()
    {
        string withUnknownAction = """{"action":"delete-everything","nonce":"BBBB","clientID":"CCCC"}""";
        Assert.Throws<EnvelopeValidationException>(() => ProtocolEnvelopeParser.Parse(withUnknownAction));
    }

    [Fact]
    public void RejectsMissingClientId()
    {
        string withoutClientId = """{"action":"get-logins","message":"AAAA","nonce":"BBBB"}""";
        Assert.Throws<EnvelopeValidationException>(() => ProtocolEnvelopeParser.Parse(withoutClientId));
    }

    [Fact]
    public void ClassifyRejectsChangePublicKeysWithMessage()
    {
        string malformed = """{"action":"change-public-keys","publicKey":"AAAA","message":"BBBB","nonce":"CCCC","clientID":"DDDD"}""";
        var envelope = ProtocolEnvelopeParser.Parse(malformed);
        Assert.Throws<EnvelopeValidationException>(() => ProtocolEnvelopeParser.Classify(envelope));
    }

    [Fact]
    public void DecodeFixedLength_WrongLength_Throws()
    {
        string base64OfWrongLength = System.Convert.ToBase64String(new byte[10]);
        Assert.Throws<EnvelopeValidationException>(() =>
            ProtocolEnvelopeParser.DecodeFixedLength(base64OfWrongLength, 32, "testField"));
    }
}