// src/root.zig
// Step 1: minimal P/Invoke skeleton for keepasshttp2.
// No network, no crypto yet - only proves the C# <-> Zig ABI boundary works
// in both directions (direct call, and Zig calling back into C#).

const std = @import("std");

// Signature the C# host must implement and register via keepasshttp2_set_callback.
// data/len: request bytes owned by Zig (valid only for the duration of the call).
// out_len: callback writes the length of its response here.
// Return value: pointer to response bytes, allocated by the C# side (caller must
// eventually free it - not handled yet, this is only a plumbing test).
pub const RequestCallback = *const fn (
    data: [*]const u8,
    len: usize,
    out_len: *usize,
) callconv(.c) ?[*]const u8;

var callback: ?RequestCallback = null;

export fn keepasshttp2_ping() callconv(.c) i32 {
    return 42;
}

export fn keepasshttp2_set_callback(cb: RequestCallback) callconv(.c) void {
    callback = cb;
}

export fn keepasshttp2_invoke_test(msg: [*]const u8, msg_len: usize) callconv(.c) i32 {
    const cb = callback orelse return -1;
    var out_len: usize = 0;
    const result = cb(msg, msg_len, &out_len);
    if (result == null) return -2;
    return @as(i32, @intCast(out_len));
}
