const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 19455);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    std.debug.print("Listening on 127.0.0.1:19455\n", .{});

    while (true) {
        const stream = server.accept(io) catch |err| {
            std.debug.print("accept error: {}\n", .{err});
            continue;
        };
        defer stream.close(io);

        std.debug.print("\nConnection accepted\n", .{});

        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buf);

        while (true) {
            const maybe_line = reader.interface.takeDelimiter('\n') catch |err| {
                std.debug.print("takeDelimiter error: {}\n", .{err});
                break;
            };
            const line = maybe_line orelse break; // null = connection closed
            const trimmed = std.mem.trimEnd(u8, line, "\r");
            std.debug.print("LINE: [{s}]\n", .{trimmed});
            if (trimmed.len == 0) break; // blank line = end of HTTP headers
        }
        std.debug.print("--- end of headers ---\n", .{});
    }
}
