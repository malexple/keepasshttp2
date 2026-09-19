// DTOs for the *decrypted* inner JSON payloads (the plaintext that comes
// out of Box.Open). These are authenticated by crypto_box (only someone
// holding a paired key could have produced them), which is a materially
// different trust level than the outer envelope — but we still parse them
// strictly into flat DTOs rather than object/dynamic, for consistency and
// because a compromised/buggy client could still send malformed JSON here.

using System.Text.Json.Serialization;

namespace KeePassHttp2.Protocol;

public sealed record InnerActionProbe
{
    [JsonPropertyName("action")]
    public string? Action { get; init; }
}

public sealed record GetLoginsRequest
{
    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("submitUrl")]
    public string? SubmitUrl { get; init; }
}
