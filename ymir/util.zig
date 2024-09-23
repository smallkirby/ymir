const std = @import("std");
const log = std.log.scoped(.util);

/// Hexdump the given memory region.
pub fn dumpMemory(addr: [*]u8, size: usize) !void {
    @fence(.seq_cst);

    const byte_per_line = 16;
    const char_per_byte = 3;
    const size_line_buf = byte_per_line * char_per_byte + 1;
    var line_buf = [_]u8{0} ** size_line_buf;

    var i: usize = 0;
    while (i < size) : (i += byte_per_line) {
        const start_addr: u64 = @intFromPtr(addr) + i;
        @memset(line_buf[0..line_buf.len], 0);

        var j: usize = 0;
        while (i + j < size and j < byte_per_line) : (j += 1) {
            const byte = addr[i + j];
            const ptr: [*]u8 = @ptrCast(&line_buf[j * char_per_byte]);
            _ = try std.fmt.bufPrint(ptr[0..char_per_byte], "{X:0>2} ", .{byte});
        }

        log.info("0x{X:0>16}: {s}", .{ start_addr, line_buf });
    }
}
