const std = @import("std");

/// Set the integer where only the nth bit is set.
pub fn tobit(T: type, nth: anytype) T {
    const val = switch (@typeInfo(@TypeOf(nth))) {
        .Int, .ComptimeInt => nth,
        .Enum => @intFromEnum(nth),
        else => @compileError("setbit: invalid type"),
    };
    return @as(T, 1) << @intCast(val);
}

/// Check if the nth bit is set.
pub inline fn isset(val: anytype, nth: anytype) bool {
    const int_nth = switch (@typeInfo(@TypeOf(nth))) {
        .Int, .ComptimeInt => nth,
        .Enum => @intFromEnum(nth),
        else => @compileError("isset: invalid type"),
    };
    return ((val >> @intCast(int_nth)) & 1) != 0;
}

/// Concatnate two values and returns new value with twice the bit width.
pub inline fn concat(T: type, a: anytype, b: @TypeOf(a)) T {
    const U = @TypeOf(a);
    const width_T = @typeInfo(T).Int.bits;
    const width_U = switch (@typeInfo(U)) {
        .Int => |t| t.bits,
        .ComptimeInt => width_T / 2,
        else => @compileError("concat: invalid type"),
    };
    if (width_T != width_U * 2) @compileError("concat: invalid type");
    return (@as(T, a) << width_U) | @as(T, b);
}

const testing = std.testing;

test "tobit" {
    try testing.expectEqual(0b0000_0001, tobit(u8, 0));
    try testing.expectEqual(0b0001_0000, tobit(u8, 4));
    try testing.expectEqual(0b1000_0000, tobit(u8, 7));
}

test "isset" {
    try testing.expectEqual(true, isset(0b10, 1));
    try testing.expectEqual(false, isset(0b10, 0));
    try testing.expectEqual(true, isset(0b1000_0000, 7));
    try testing.expectEqual(false, isset(0b1000_0000, 99));
}

test "concat" {
    try testing.expectEqual(0b10, concat(u2, @as(u1, 1), @as(u1, 0)));
    try testing.expectEqual(0x1234, concat(u16, 0x12, 0x34));
}
