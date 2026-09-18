// TCP -> WebSocket handshake -> frame echo server.
// Building blocks verified in isolation first:
//   - accept-loop + line reading: tcp_probe.zig
//   - Sec-WebSocket-Accept (SHA1+Base64): ws_accept_test.zig
//   - frame decode/encode logic: ws_frame_test.zig
//
// NOTE: take(n) blocks until exactly n bytes are available, it does NOT
// return "whatever is available up to n". So frames must be read in
// exact-size steps (header -> extended length -> mask -> payload),
// never with one oversized take() call.

const std = @import("std");

fn buildFrame(out: []u8, opcode: u4, payload: []const u8) ![]u8 {
    if (payload.len > 125) return error.PayloadTooLargeForTest;
    if (out.len < 2 + payload.len) return error.OutputTooSmall;

    out[0] = 0x80 | @as(u8, opcode);
    out[1] = @intCast(payload.len);
    @memcpy(out[2 .. 2 + payload.len], payload);
    return out[0 .. 2 + payload.len];
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 19455);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);

    std.debug.print("Listening on 127.0.0.1:19455\n", .{});

    while (true) {
        var stream = try server.accept(io);
        defer stream.close(io);
        std.debug.print("\nConnection accepted\n", .{});

        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buf);

        var ws_key_buf: [256]u8 = undefined;
        var ws_key_len: usize = 0;

        while (true) {
            const maybe_line = reader.interface.takeDelimiter('\n') catch |err| {
                std.debug.print("read error: {}\n", .{err});
                break;
            };
            const line = maybe_line orelse {
                std.debug.print("EOF before end of headers\n", .{});
                break;
            };
            const trimmed = std.mem.trimEnd(u8, line, "\r\n");
            std.debug.print("LINE: [{s}]\n", .{trimmed});
            if (trimmed.len == 0) {
                std.debug.print("--- end of headers ---\n", .{});
                break;
            }

            const prefix = "Sec-WebSocket-Key: ";
            if (std.mem.startsWith(u8, trimmed, prefix)) {
                const value = trimmed[prefix.len..];
                @memcpy(ws_key_buf[0..value.len], value);
                ws_key_len = value.len;
            }
        }

        if (ws_key_len == 0) {
            std.debug.print("No Sec-WebSocket-Key found, skipping\n", .{});
            continue;
        }
        const key = ws_key_buf[0..ws_key_len];

        const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var concat_buf: [256]u8 = undefined;
        const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ key, guid });

        var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat, &hash, .{});

        var accept_buf: [64]u8 = undefined;
        const accept = std.base64.standard.Encoder.encode(&accept_buf, &hash);

        var response_buf: [512]u8 = undefined;
        const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "\r\n", .{accept});

        var write_buf: [512]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        try writer.interface.writeAll(response);
        try writer.interface.flush();

        std.debug.print("Sent 101 response, Accept: {s}\n", .{accept});

        // --- WebSocket frame echo loop ---
        var frame_read_buf: [4096]u8 = undefined;
        var frame_reader = stream.reader(io, &frame_read_buf);

        conn: while (true) {
            const header = frame_reader.interface.take(2) catch |err| {
                std.debug.print("frame read error (header): {}\n", .{err});
                break :conn;
            };
            const byte0 = header[0];
            const byte1 = header[1];
            const fin = (byte0 & 0x80) != 0;
            const opcode: u4 = @intCast(byte0 & 0x0f);
            const masked = (byte1 & 0x80) != 0;
            const len7: u64 = byte1 & 0x7f;

            var payload_len: u64 = len7;
            if (len7 == 126) {
                const ext = frame_reader.interface.take(2) catch |err| {
                    std.debug.print("frame read error (len16): {}\n", .{err});
                    break :conn;
                };
                payload_len = std.mem.readInt(u16, ext[0..2], .big);
            } else if (len7 == 127) {
                const ext = frame_reader.interface.take(8) catch |err| {
                    std.debug.print("frame read error (len64): {}\n", .{err});
                    break :conn;
                };
                payload_len = std.mem.readInt(u64, ext[0..8], .big);
            }

            var mask_key: [4]u8 = undefined;
            if (masked) {
                const mk = frame_reader.interface.take(4) catch |err| {
                    std.debug.print("frame read error (mask): {}\n", .{err});
                    break :conn;
                };
                @memcpy(&mask_key, mk);
            }

            if (payload_len > 4096) {
                std.debug.print("payload too large for demo: {}\n", .{payload_len});
                break :conn;
            }

            var decode_buf: [4096]u8 = undefined;
            const payload_len_usize: usize = @intCast(payload_len);
            var payload: []const u8 = decode_buf[0..0];
            if (payload_len_usize > 0) {
                const raw = frame_reader.interface.take(payload_len_usize) catch |err| {
                    std.debug.print("frame read error (payload): {}\n", .{err});
                    break :conn;
                };
                if (masked) {
                    for (raw, 0..) |b, i| decode_buf[i] = b ^ mask_key[i % 4];
                } else {
                    @memcpy(decode_buf[0..payload_len_usize], raw);
                }
                payload = decode_buf[0..payload_len_usize];
            }

            std.debug.print("FRAME opcode={} fin={} payload=\"{s}\"\n", .{ opcode, fin, payload });

            if (opcode == 0x8) {
                std.debug.print("received close frame\n", .{});
                break :conn;
            }

            if (opcode == 0x1) {
                var echo_buf: [4096]u8 = undefined;
                const echo_frame = try buildFrame(&echo_buf, 0x1, payload);
                try writer.interface.writeAll(echo_frame);
                try writer.interface.flush();
                std.debug.print("echoed back \"{s}\"\n", .{payload});
            }
        }
    }
}