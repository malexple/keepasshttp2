// TCP echo -> full WebSocket handshake server.
// Reuses the accept-loop and line-reading pattern from tcp_probe.zig
// (Step 2), plus the SHA1+Base64 logic verified in ws_accept_test.zig.

const std = @import("std");

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
    }
}