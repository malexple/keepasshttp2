// Strict, flat DTO for the top-level KeePassXC-Browser protocol JSON.
// Parsed by hand via KeePassHttp2.Json (no System.Text.Json, no NuGet) -
// every field is read out explicitly by name and expected type; nothing
// beyond these exact fields can end up on this object.
//
// Wire shapes (see keepassxc-protocol.md / Protocol V2 draft):
//   change-public-keys (plaintext): action, publicKey, nonce, clientID
//   everything else (message encrypted): action, message, nonce, clientID,
//                                         requestID?, triggerUnlock?

using System;
using KeePassHttp2.Json;

namespace KeePassHttp2.Protocol;

public sealed record ProtocolEnvelope
{
    public string? Action { get; init; }
    public string? ClientId { get; init; }
    public string? Nonce { get; init; }

    // Only present for change-public-keys (plaintext key exchange).
    public string? PublicKey { get; init; }

    // Only present for encrypted actions (base64 crypto_box ciphertext).
    public string? Message { get; init; }

    public string? RequestId { get; init; }
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

    // The only field names a valid envelope may contain. Anything extra
    // is rejected outright - this replaces the strictness that
    // System.Text.Json's UnmappedMemberHandling.Disallow used to give us.
    private static readonly string[] KnownFields =
    [
        "action", "clientID", "nonce", "publicKey", "message", "requestID", "triggerUnlock",
    ];

    public static ProtocolEnvelope Parse(string rawJson)
    {
        JsonValue root;
        try
        {
            root = JsonParser.Parse(rawJson);
        }
        catch (JsonException ex)
        {
            throw new EnvelopeValidationException($"malformed JSON: {ex.Message}");
        }

        if (root.Kind != JsonKind.Object)
            throw new EnvelopeValidationException("envelope must be a JSON object");

        foreach (var key in root.Keys)
        {
            if (Array.IndexOf(KnownFields, key) < 0)
                throw new EnvelopeValidationException($"unexpected field: {key}");
        }

        ProtocolEnvelope envelope;
        try
        {
            envelope = new ProtocolEnvelope
            {
                Action = root.TryGetString("action"),
                ClientId = root.TryGetString("clientID"),
                Nonce = root.TryGetString("nonce"),
                PublicKey = root.TryGetString("publicKey"),
                Message = root.TryGetString("message"),
                RequestId = root.TryGetString("requestID"),
                TriggerUnlock = root.TryGetBool("triggerUnlock"),
            };
        }
        catch (JsonException ex)
        {
            throw new EnvelopeValidationException(ex.Message);
        }

        if (string.IsNullOrEmpty(envelope.Action) || Array.IndexOf(KnownActions, envelope.Action) < 0)
            throw new EnvelopeValidationException($"unknown action: {envelope.Action}");

        if (string.IsNullOrEmpty(envelope.ClientId))
            throw new EnvelopeValidationException("missing clientID");

        if (string.IsNullOrEmpty(envelope.Nonce))
            throw new EnvelopeValidationException("missing nonce");

        return envelope;
    }

    // Classifies + validates field presence/shape for the two wire forms.
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
    // fixed sizes per the crypto_box primitive: 32-byte keys, 24-byte nonce).
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