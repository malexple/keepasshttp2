// Isolated test: compute Sec-WebSocket-Accept for the RFC 6455 example key
// and compare against the known-correct value from the spec itself.
// Expected: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

const std = @import("std");

pub fn main() !void {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    var concat_buf: [128]u8 = undefined;
    const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ key, guid });

    var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(concat, &hash, .{});

    var b64_buf: [64]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&b64_buf, &hash);

    std.debug.print("Computed: {s}\n", .{encoded});
    std.debug.print("Expected: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\n", .{});

    if (std.mem.eql(u8, encoded, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) {
        std.debug.print("MATCH\n", .{});
    } else {
        std.debug.print("MISMATCH\n", .{});
    }
}
