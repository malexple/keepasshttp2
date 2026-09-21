// DTOs for the *decrypted* inner JSON payloads (the plaintext that comes
// out of NaClBox.Open). These are authenticated by crypto_box (only
// someone holding a paired key could have produced them), which is a
// materially different trust level than the outer envelope - but we still
// parse them strictly via KeePassHttp2.Json rather than trusting shape,
// because a compromised/buggy client could still send malformed JSON here.

using KeePassHttp2.Json;

namespace KeePassHttp2.Protocol;

public sealed record InnerActionProbe
{
    public string? Action { get; init; }

    public static InnerActionProbe Parse(JsonValue root) => new()
    {
        Action = root.TryGetString("action"),
    };
}

public sealed record GetLoginsRequest
{
    public string? Action { get; init; }
    public string? Url { get; init; }
    public string? SubmitUrl { get; init; }

    public static GetLoginsRequest Parse(JsonValue root) => new()
    {
        Action = root.TryGetString("action"),
        Url = root.TryGetString("url"),
        SubmitUrl = root.TryGetString("submitUrl"),
    };
}

// "key" here is the *session* client public key (the one sent earlier in
// change-public-keys) - it's a self-attestation the caller includes so we
// can sanity-check the encrypted associate message really belongs to the
// session we think it does. "idKey" is the new, permanent identification
// public key the client wants us to remember it by.
public sealed record AssociateRequest
{
    public string? Action { get; init; }
    public string? Key { get; init; }
    public string? IdKey { get; init; }

    public static AssociateRequest Parse(JsonValue root) => new()
    {
        Action = root.TryGetString("action"),
        Key = root.TryGetString("key"),
        IdKey = root.TryGetString("idKey"),
    };
}

// "id" is the association name chosen at associate-time. "key" here is the
// permanent identification public key (not a session key) - we look up
// "id" and compare against what we stored for it.
public sealed record TestAssociateRequest
{
    public string? Action { get; init; }
    public string? Id { get; init; }
    public string? Key { get; init; }

    public static TestAssociateRequest Parse(JsonValue root) => new()
    {
        Action = root.TryGetString("action"),
        Id = root.TryGetString("id"),
        Key = root.TryGetString("key"),
    };
}