// TCP -> WebSocket handshake -> frame echo server, with protocol-level
// conformance (ping/pong, close handshake) and Origin validation to block
// cross-site WebSocket hijacking from arbitrary web pages.
//
// Building blocks verified in isolation first:
//   - accept-loop + line reading: tcp_probe.zig
//   - Sec-WebSocket-Accept (SHA1+Base64): ws_accept_test.zig
//   - frame decode/encode logic: ws_frame_test.zig
//
// NOTE: take(n) blocks until exactly n bytes are available, so frames are
// read in exact-size steps (header -> extended length -> mask -> payload).

const std = @import("std");

// Official KeePassXC-Browser extension on the Chrome Web Store.
// Add any dev/unpacked extension ID here too while testing locally.
const allowed_chrome_origins = [_][]const u8{
    "chrome-extension://oboonakemofpalcgghocfoadofidjkkk",
};

// Firefox assigns a random per-install UUID to moz-extension:// URLs
// specifically so it *cannot* be hardcoded or used for fingerprinting.
// A malicious web page's JS cannot spoof this scheme regardless, so
// accepting any moz-extension:// origin is sufficient to block the
// cross-site WebSocket hijacking threat this check exists for.
const moz_extension_prefix = "moz-extension://";

fn isOriginAllowed(origin: []const u8) bool {
    for (allowed_chrome_origins) |allowed| {
        if (std.mem.eql(u8, origin, allowed)) return true;
    }
    return std.mem.startsWith(u8, origin, moz_extension_prefix);
}

fn buildFrame(out: []u8, opcode: u4, payload: []const u8) ![]u8 {
    if (payload.len > 125) return error.PayloadTooLargeForTest;
    if (out.len < 2 + payload.len) return error.OutputTooSmall;

    out[0] = 0x80 | @as(u8, opcode);
    out[1] = @intCast(payload.len);
    @memcpy(out[2 .. 2 + payload.len], payload);
    return out[0 .. 2 + payload.len];
}

fn sendClose(writer: anytype, code: u16, reason: []const u8) !void {
    var payload_buf: [125]u8 = undefined;
    std.mem.writeInt(u16, payload_buf[0..2], code, .big);
    @memcpy(payload_buf[2 .. 2 + reason.len], reason);

    var out_buf: [128]u8 = undefined;
    const frame = try buildFrame(&out_buf, 0x8, payload_buf[0 .. 2 + reason.len]);
    try writer.interface.writeAll(frame);
    try writer.interface.flush();
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
        var origin_buf: [256]u8 = undefined;
        var origin_len: usize = 0;

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

            const key_prefix = "Sec-WebSocket-Key: ";
            if (std.mem.startsWith(u8, trimmed, key_prefix)) {
                const value = trimmed[key_prefix.len..];
                @memcpy(ws_key_buf[0..value.len], value);
                ws_key_len = value.len;
            }

            const origin_prefix = "Origin: ";
            if (std.mem.startsWith(u8, trimmed, origin_prefix)) {
                const value = trimmed[origin_prefix.len..];
                @memcpy(origin_buf[0..value.len], value);
                origin_len = value.len;
            }
        }

        if (ws_key_len == 0) {
            std.debug.print("No Sec-WebSocket-Key found, skipping\n", .{});
            continue;
        }

        const origin = origin_buf[0..origin_len];
        if (origin_len == 0 or !isOriginAllowed(origin)) {
            std.debug.print("REJECTED origin: \"{s}\"\n", .{origin});
            var write_buf: [256]u8 = undefined;
            var writer = stream.writer(io, &write_buf);
            const forbidden = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
            writer.interface.writeAll(forbidden) catch {};
            writer.interface.flush() catch {};
            continue;
        }
        std.debug.print("Origin allowed: \"{s}\"\n", .{origin});

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

        // --- WebSocket frame loop ---
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

            // RFC 6455 5.1: the server MUST close the connection upon
            // receiving a non-masked frame from a client.
            if (!masked) {
                std.debug.print("protocol error: unmasked frame from client\n", .{});
                sendClose(&writer, 1002, "expected masked frame") catch {};
                break :conn;
            }

            var mask_key: [4]u8 = undefined;
            const mk = frame_reader.interface.take(4) catch |err| {
                std.debug.print("frame read error (mask): {}\n", .{err});
                break :conn;
            };
            @memcpy(&mask_key, mk);

            if (payload_len > 4096) {
                std.debug.print("payload too large for demo: {}\n", .{payload_len});
                sendClose(&writer, 1009, "message too big") catch {};
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
                for (raw, 0..) |b, i| decode_buf[i] = b ^ mask_key[i % 4];
                payload = decode_buf[0..payload_len_usize];
            }

            std.debug.print("FRAME opcode={} fin={} len={}\n", .{ opcode, fin, payload_len_usize });

            switch (opcode) {
                0x1 => { // text
                    std.debug.print("payload=\"{s}\"\n", .{payload});
                    var echo_buf: [4096]u8 = undefined;
                    const echo_frame = try buildFrame(&echo_buf, 0x1, payload);
                    try writer.interface.writeAll(echo_frame);
                    try writer.interface.flush();
                    std.debug.print("echoed back \"{s}\"\n", .{payload});
                },
                0x8 => { // close
                    std.debug.print("received close frame, replying and closing\n", .{});
                    if (payload.len >= 2) {
                        const code = std.mem.readInt(u16, payload[0..2], .big);
                        std.debug.print("close code={} reason=\"{s}\"\n", .{ code, payload[2..] });
                        sendClose(&writer, code, "") catch {};
                    } else {
                        sendClose(&writer, 1000, "") catch {};
                    }
                    break :conn;
                },
                0x9 => { // ping -> must reply with pong carrying same payload
                    std.debug.print("received ping, sending pong\n", .{});
                    var pong_buf: [128]u8 = undefined;
                    const pong_frame = try buildFrame(&pong_buf, 0xA, payload);
                    try writer.interface.writeAll(pong_frame);
                    try writer.interface.flush();
                },
                0xA => { // unsolicited pong -> ignore
                    std.debug.print("received pong, ignoring\n", .{});
                },
                else => {
                    std.debug.print("unhandled opcode {}, ignoring\n", .{opcode});
                },
            }
        }
    }
}