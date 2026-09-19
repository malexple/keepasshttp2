// Strict, flat DTO for the top-level KeePassXC-Browser protocol JSON.
// Deserialized with System.Text.Json only — no polymorphic types, no
// TypeNameHandling, no `object`/`dynamic` fields. This is untrusted network
// input, decrypted or not, so the parser must not be able to construct
// anything beyond these exact string/bool fields.
//
// Wire shapes (see keepassxc-protocol.md / Protocol V2 draft):
//   change-public-keys (plaintext): action, publicKey, nonce, clientID
//   everything else (message encrypted): action, message, nonce, clientID,
//                                         requestID?, triggerUnlock?

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeePassHttp2.Protocol;

public sealed record ProtocolEnvelope
{
    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("clientID")]
    public string? ClientId { get; init; }

    [JsonPropertyName("nonce")]
    public string? Nonce { get; init; }

    // Only present for change-public-keys (plaintext key exchange).
    [JsonPropertyName("publicKey")]
    public string? PublicKey { get; init; }

    // Only present for encrypted actions (base64 nacl.box ciphertext).
    [JsonPropertyName("message")]
    public string? Message { get; init; }

    [JsonPropertyName("requestID")]
    public string? RequestId { get; init; }

    [JsonPropertyName("triggerUnlock")]
    public bool? TriggerUnlock { get; init; }
}

public enum EnvelopeKind
{
    ChangePublicKeys,
    Encrypted,
}

public sealed class EnvelopeValidationException(string reason) : Exception(reason);

public static class ProtocolEnvelopeParser
{
    // Every action we currently understand. Anything else is rejected
    // before it can reach any business logic.
    private static readonly string[] KnownActions =
    [
        "change-public-keys",
        "associate",
        "get-logins",
        "get-logins-count",
        "generate-password",
        "lock-database",
        "test-associate",
    ];

    private static readonly JsonSerializerOptions StrictOptions = new()
    {
        // A valid envelope is exactly one flat object. Depth 2 accounts for
        // the root object itself; nothing may nest an object or array inside
        // any field.
        MaxDepth = 2,
        AllowTrailingCommas = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
    };

    public static ProtocolEnvelope Parse(string rawJson)
    {
        ProtocolEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<ProtocolEnvelope>(rawJson, StrictOptions);
        }
        catch (JsonException ex)
        {
            throw new EnvelopeValidationException($"malformed JSON: {ex.Message}");
        }

        if (envelope is null)
            throw new EnvelopeValidationException("empty envelope");

        if (string.IsNullOrEmpty(envelope.Action) || Array.IndexOf(KnownActions, envelope.Action) < 0)
            throw new EnvelopeValidationException($"unknown action: {envelope.Action}");

        if (string.IsNullOrEmpty(envelope.ClientId))
            throw new EnvelopeValidationException("missing clientID");

        if (string.IsNullOrEmpty(envelope.Nonce))
            throw new EnvelopeValidationException("missing nonce");

        return envelope;
    }

    // Classifies + validates field presence/shape for the two wire forms.
    // Returns exact decoded byte lengths the caller must pass on to the
    // Zig P/Invoke boundary — never the raw network-supplied lengths.
    public static EnvelopeKind Classify(ProtocolEnvelope envelope)
    {
        if (envelope.Action == "change-public-keys")
        {
            if (string.IsNullOrEmpty(envelope.PublicKey))
                throw new EnvelopeValidationException("change-public-keys missing publicKey");
            if (envelope.Message is not null)
                throw new EnvelopeValidationException("change-public-keys must not carry message");
            return EnvelopeKind.ChangePublicKeys;
        }

        if (string.IsNullOrEmpty(envelope.Message))
            throw new EnvelopeValidationException($"{envelope.Action} missing message");
        if (envelope.PublicKey is not null)
            throw new EnvelopeValidationException($"{envelope.Action} must not carry publicKey");
        return EnvelopeKind.Encrypted;
    }

    // Strict base64 decode with an exact expected length (keys/nonces have
    // fixed sizes per the NaCl box primitive: 32-byte keys, 24-byte nonce).
    // Never trust the network to tell us how long its own data is.
    public static byte[] DecodeFixedLength(string base64, int expectedLength, string fieldName)
    {
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new EnvelopeValidationException($"{fieldName}: invalid base64");
        }

        if (decoded.Length != expectedLength)
            throw new EnvelopeValidationException(
                $"{fieldName}: expected {expectedLength} bytes, got {decoded.Length}");

        return decoded;
    }
}
