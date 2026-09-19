// Combined C-ABI library: WebSocket transport + crypto_box, exported for
// P/Invoke from the C# plugin.
//
// Design: synchronous, blocking, poll-style API. No callbacks cross the
// P/Invoke boundary. C# drives the loop itself:
//   kp2_ws_listen -> kp2_ws_accept -> loop { kp2_ws_recv, kp2_ws_send } -> kp2_ws_close

const std = @import("std");
const Box = std.crypto.nacl.Box;

const allowed_chrome_origins = [_][]const u8{
    "chrome-extension://oboonakemofpalcgghocfoadofidjkkk",
};
const moz_extension_prefix = "moz-extension://";

fn isOriginAllowed(origin: []const u8) bool {
    for (allowed_chrome_origins) |allowed| {
        if (std.mem.eql(u8, origin, allowed)) return true;
    }
    return std.mem.startsWith(u8, origin, moz_extension_prefix);
}

fn buildFrame(out: []u8, opcode: u4, payload: []const u8) ![]u8 {
    if (payload.len > 125) return error.PayloadTooLargeForControlFrame;
    if (out.len < 2 + payload.len) return error.OutputTooSmall;
    out[0] = 0x80 | @as(u8, opcode);
    out[1] = @intCast(payload.len);
    @memcpy(out[2 .. 2 + payload.len], payload);
    return out[0 .. 2 + payload.len];
}

const max_connections = 8;

var g_io_threaded: ?std.Io.Threaded = null;
var g_server: ?std.Io.net.Server = null;

const Connection = struct {
    stream: std.Io.net.Stream,
    read_buf: [8192]u8 = undefined,
    write_buf: [8192]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    in_use: bool = false,
};

var g_connections: [max_connections]Connection = undefined;

fn io() std.Io {
    if (g_io_threaded == null) {
        g_io_threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    }
    return g_io_threaded.?.io();
}

export fn kp2_ws_listen(port: u16) callconv(.c) i32 {
    const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return -1;
    g_server = addr.listen(io(), .{}) catch return -2;
    for (&g_connections) |*c| c.in_use = false;
    return 0;
}

export fn kp2_ws_shutdown() callconv(.c) void {
    if (g_server) |*s| s.deinit(io());
    g_server = null;
}

export fn kp2_ws_accept() callconv(.c) i32 {
    const server = &(g_server orelse return -2);

    var slot: ?usize = null;
    for (&g_connections, 0..) |*c, i| {
        if (!c.in_use) {
            slot = i;
            break;
        }
    }
    const idx = slot orelse return -1;
    const conn = &g_connections[idx];

    conn.stream = server.accept(io()) catch return -2;
    conn.reader = conn.stream.reader(io(), &conn.read_buf);

    var ws_key_buf: [256]u8 = undefined;
    var ws_key_len: usize = 0;
    var origin_buf: [256]u8 = undefined;
    var origin_len: usize = 0;

    while (true) {
        const maybe_line = conn.reader.interface.takeDelimiter('\n') catch {
            conn.stream.close(io());
            return -2;
        };
        const line = maybe_line orelse break;
        const trimmed = std.mem.trimEnd(u8, line, "\r\n");
        if (trimmed.len == 0) break;

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
        conn.stream.close(io());
        return -3;
    }

    const origin = origin_buf[0..origin_len];
    conn.writer = conn.stream.writer(io(), &conn.write_buf);

    if (origin_len == 0 or !isOriginAllowed(origin)) {
        const forbidden = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
        conn.writer.interface.writeAll(forbidden) catch {};
        conn.writer.interface.flush() catch {};
        conn.stream.close(io());
        return -4;
    }

    const key = ws_key_buf[0..ws_key_len];
    const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var concat_buf: [256]u8 = undefined;
    const concat = std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ key, guid }) catch unreachable;

    var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(concat, &hash, .{});

    var accept_buf: [64]u8 = undefined;
    const accept = std.base64.standard.Encoder.encode(&accept_buf, &hash);

    var response_buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n", .{accept}) catch unreachable;

    conn.writer.interface.writeAll(response) catch {
        conn.stream.close(io());
        return -5;
    };
    conn.writer.interface.flush() catch {
        conn.stream.close(io());
        return -5;
    };

    conn.in_use = true;
    return @intCast(idx);
}

fn connFromHandle(handle: i32) ?*Connection {
    if (handle < 0 or handle >= max_connections) return null;
    const conn = &g_connections[@intCast(handle)];
    if (!conn.in_use) return null;
    return conn;
}

export fn kp2_ws_recv(handle: i32, out_buf: [*]u8, out_buf_len: usize) callconv(.c) i32 {
    const conn = connFromHandle(handle) orelse return -1;

    while (true) {
        const header = conn.reader.interface.take(2) catch return closeAndReturn(conn, 0);
        const byte0 = header[0];
        const byte1 = header[1];
        const opcode: u4 = @intCast(byte0 & 0x0f);
        const masked = (byte1 & 0x80) != 0;
        const len7: u64 = byte1 & 0x7f;

        var payload_len: u64 = len7;
        if (len7 == 126) {
            const ext = conn.reader.interface.take(2) catch return closeAndReturn(conn, 0);
            payload_len = std.mem.readInt(u16, ext[0..2], .big);
        } else if (len7 == 127) {
            const ext = conn.reader.interface.take(8) catch return closeAndReturn(conn, 0);
            payload_len = std.mem.readInt(u64, ext[0..8], .big);
        }

        if (!masked) return closeAndReturn(conn, 0);

        var mask_key: [4]u8 = undefined;
        const mk = conn.reader.interface.take(4) catch return closeAndReturn(conn, 0);
        @memcpy(&mask_key, mk);

        if (payload_len > out_buf_len) return closeAndReturn(conn, 0);
        const payload_len_usize: usize = @intCast(payload_len);

        if (payload_len_usize > 0) {
            const raw = conn.reader.interface.take(payload_len_usize) catch return closeAndReturn(conn, 0);
            for (raw, 0..) |b, i| out_buf[i] = b ^ mask_key[i % 4];
        }

        switch (opcode) {
            0x1 => return @intCast(payload_len_usize),
            0x8 => return closeAndReturn(conn, 0),
            0x9 => {
                var pong_buf: [128]u8 = undefined;
                const pong_frame = buildFrame(&pong_buf, 0xA, out_buf[0..payload_len_usize]) catch continue;
                conn.writer.interface.writeAll(pong_frame) catch return closeAndReturn(conn, 0);
                conn.writer.interface.flush() catch return closeAndReturn(conn, 0);
            },
            else => {},
        }
    }
}

fn closeAndReturn(conn: *Connection, value: i32) i32 {
    conn.stream.close(io());
    conn.in_use = false;
    return value;
}

export fn kp2_ws_send(handle: i32, buf: [*]const u8, buf_len: usize) callconv(.c) i32 {
    const conn = connFromHandle(handle) orelse return -1;
    if (buf_len > 8192 - 10) return -2;

    var frame_buf: [8192]u8 = undefined;
    const frame = buildTextFrame(&frame_buf, buf[0..buf_len]) catch return -3;

    conn.writer.interface.writeAll(frame) catch return -4;
    conn.writer.interface.flush() catch return -4;
    return 0;
}

fn buildTextFrame(out: []u8, payload: []const u8) ![]u8 {
    if (payload.len <= 125) return buildFrame(out, 0x1, payload);
    if (payload.len > 65535) return error.PayloadTooLarge;
    if (out.len < 4 + payload.len) return error.OutputTooSmall;
    out[0] = 0x80 | 0x1;
    out[1] = 126;
    std.mem.writeInt(u16, out[2..4], @intCast(payload.len), .big);
    @memcpy(out[4 .. 4 + payload.len], payload);
    return out[0 .. 4 + payload.len];
}

export fn kp2_ws_close(handle: i32) callconv(.c) void {
    const conn = connFromHandle(handle) orelse return;
    var close_buf: [4]u8 = undefined;
    std.mem.writeInt(u16, close_buf[0..2], 1000, .big);
    const frame = buildFrame(&close_buf, 0x8, close_buf[0..2]) catch {
        _ = closeAndReturn(conn, 0);
        return;
    };
    conn.writer.interface.writeAll(frame) catch {};
    conn.writer.interface.flush() catch {};
    _ = closeAndReturn(conn, 0);
}

// --- Crypto exports ---

export fn kp2_box_open(
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    nonce: [*]const u8,
    nonce_len: usize,
    public_key: [*]const u8,
    public_key_len: usize,
    secret_key: [*]const u8,
    secret_key_len: usize,
    out_plaintext: [*]u8,
    out_plaintext_len: usize,
) callconv(.c) i32 {
    if (nonce_len != Box.nonce_length) return -1;
    if (public_key_len != Box.public_length) return -2;
    if (secret_key_len != Box.secret_length) return -3;
    if (ciphertext_len < Box.tag_length) return -4;

    const plaintext_len = ciphertext_len - Box.tag_length;
    if (out_plaintext_len < plaintext_len) return -5;

    Box.open(
        out_plaintext[0..plaintext_len],
        ciphertext[0..ciphertext_len],
        nonce[0..Box.nonce_length].*,
        public_key[0..Box.public_length].*,
        secret_key[0..Box.secret_length].*,
    ) catch return -6;

    return @intCast(plaintext_len);
}

export fn kp2_box_seal(
    message: [*]const u8,
    message_len: usize,
    nonce: [*]const u8,
    nonce_len: usize,
    public_key: [*]const u8,
    public_key_len: usize,
    secret_key: [*]const u8,
    secret_key_len: usize,
    out_ciphertext: [*]u8,
    out_ciphertext_len: usize,
) callconv(.c) i32 {
    if (nonce_len != Box.nonce_length) return -1;
    if (public_key_len != Box.public_length) return -2;
    if (secret_key_len != Box.secret_length) return -3;

    const ciphertext_len = message_len + Box.tag_length;
    if (out_ciphertext_len < ciphertext_len) return -5;

    Box.seal(
        out_ciphertext[0..ciphertext_len],
        message[0..message_len],
        nonce[0..Box.nonce_length].*,
        public_key[0..Box.public_length].*,
        secret_key[0..Box.secret_length].*,
    ) catch return -6;

    return @intCast(ciphertext_len);
}

export fn kp2_secure_zero(buf: [*]u8, len: usize) callconv(.c) void {
    std.crypto.secureZero(u8, buf[0..len]);
}

// Generates a fresh X25519 keypair for the host side of the key exchange.
// Written to out_public/out_secret, which must each be exactly 32 bytes.
export fn kp2_generate_keypair(out_public: [*]u8, out_public_len: usize, out_secret: [*]u8, out_secret_len: usize) callconv(.c) i32 {
    if (out_public_len != Box.public_length) return -1;
    if (out_secret_len != Box.secret_length) return -2;

    const kp = Box.KeyPair.generate(io());
    @memcpy(out_public[0..Box.public_length], &kp.public_key);
    @memcpy(out_secret[0..Box.secret_length], &kp.secret_key);
    return 0;
}
