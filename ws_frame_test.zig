// Isolated test: WebSocket frame parsing/building, pure logic, no sockets.
// Test vector is the exact example from RFC 6455 section 5.7:
// A single-frame masked text message "Hello" from a client is:
//   0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58

const std = @import("std");

const Frame = struct {
    fin: bool,
    opcode: u4,
    payload: []const u8,
};

// Parses one frame from `buf`, unmasking the payload into `out` if masked.
// Returns the parsed frame plus the number of bytes consumed.
fn parseFrame(buf: []const u8, out: []u8) !struct { frame: Frame, consumed: usize } {
    if (buf.len < 2) return error.Incomplete;

    const byte0 = buf[0];
    const fin = (byte0 & 0x80) != 0;
    const opcode: u4 = @intCast(byte0 & 0x0f);

    const byte1 = buf[1];
    const masked = (byte1 & 0x80) != 0;
    const len7: u64 = byte1 & 0x7f;

    var pos: usize = 2;
    var payload_len: u64 = len7;
    if (len7 == 126) {
        if (buf.len < pos + 2) return error.Incomplete;
        payload_len = std.mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
    } else if (len7 == 127) {
        if (buf.len < pos + 8) return error.Incomplete;
        payload_len = std.mem.readInt(u64, buf[pos..][0..8], .big);
        pos += 8;
    }

    var mask_key: [4]u8 = undefined;
    if (masked) {
        if (buf.len < pos + 4) return error.Incomplete;
        @memcpy(&mask_key, buf[pos .. pos + 4]);
        pos += 4;
    }

    if (buf.len < pos + payload_len) return error.Incomplete;
    const raw_payload = buf[pos .. pos + payload_len];
    pos += payload_len;

    if (masked) {
        if (out.len < payload_len) return error.OutputTooSmall;
        for (raw_payload, 0..) |b, i| {
            out[i] = b ^ mask_key[i % 4];
        }
        return .{ .frame = .{ .fin = fin, .opcode = opcode, .payload = out[0..payload_len] }, .consumed = pos };
    } else {
        return .{ .frame = .{ .fin = fin, .opcode = opcode, .payload = raw_payload }, .consumed = pos };
    }
}

// Builds an unmasked frame (server -> client never masks).
fn buildFrame(out: []u8, opcode: u4, payload: []const u8) ![]u8 {
    if (payload.len > 125) return error.PayloadTooLargeForTest;
    if (out.len < 2 + payload.len) return error.OutputTooSmall;

    out[0] = 0x80 | @as(u8, opcode);
    out[1] = @intCast(payload.len);
    @memcpy(out[2 .. 2 + payload.len], payload);
    return out[0 .. 2 + payload.len];
}

pub fn main() !void {
    const client_frame = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };

    var decode_buf: [64]u8 = undefined;
    const result = try parseFrame(&client_frame, &decode_buf);

    std.debug.print("fin={} opcode={} payload=\"{s}\" consumed={}\n", .{
        result.frame.fin, result.frame.opcode, result.frame.payload, result.consumed,
    });

    const decode_ok = result.frame.fin and result.frame.opcode == 0x1 and
        std.mem.eql(u8, result.frame.payload, "Hello") and result.consumed == client_frame.len;
    std.debug.print("DECODE: {s}\n", .{if (decode_ok) "MATCH" else "MISMATCH"});

    var encode_buf: [64]u8 = undefined;
    const server_frame = try buildFrame(&encode_buf, 0x1, "Hello");
    const expected_server_frame = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };

    std.debug.print("built frame: {x}\n", .{server_frame});
    const encode_ok = std.mem.eql(u8, server_frame, &expected_server_frame);
    std.debug.print("ENCODE: {s}\n", .{if (encode_ok) "MATCH" else "MISMATCH"});
}
