/// Set the integer where only the nth bit is set.
pub fn setbit(T: type, nth: anytype) T {
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
    if (@bitSizeOf(T) != @bitSizeOf(U) * 2) @compileError("concat: invalid type");
    return (@as(T, a) << @bitSizeOf(U)) | @as(T, b);
}
