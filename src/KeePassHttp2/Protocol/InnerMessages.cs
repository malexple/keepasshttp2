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