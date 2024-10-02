const std = @import("std");

const ymir = @import("ymir");
const mem = ymir.mem;

const am = @import("../asm.zig");

pub const VmxError = error{
    /// VMCS pointer is invalid. No status available.
    VmxStatusUnavailable,
    /// VMCS pointer is valid but the operation failed.
    /// If a current VMCS is active, error status is stored in VM-instruction error field.
    VmxStatusAvailable,
    /// Failed to allocate memory.
    OutOfMemory,
    /// Failed to subscribe to interrupts.
    InterruptFull,
};

/// Read RFLAGS and checks if a VMX instruction has failed.
pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: am.FlagsRegister = @bitCast(rflags);
    return if (flags.cf) VmxError.VmxStatusUnavailable else if (flags.zf) VmxError.VmxStatusAvailable;
}

/// VMREAD.
/// `field` is a encoded VMCS field.
/// If the operation succeeds, the value of the field is returned.
/// Regardless of the field length, this function returns a 64-bit value.
/// If the operation fails, an error is returned.
pub fn vmread(field: anytype) VmxError!u64 {
    var rflags: u64 = undefined;
    const ret = asm volatile (
        \\vmread %[field], %[ret]
        \\pushf
        \\popq %[rflags]
        : [ret] "={rax}" (-> u64),
          [rflags] "=r" (rflags),
        : [field] "r" (@as(u64, @intFromEnum(field))),
    );
    try vmxtry(rflags);
    return ret;
}

/// VMWRITE.
/// `field` is a encoded VMCS field.
/// `value` is a value to write to the field.
/// `value` can be either of the following types:
///     - integer (including comptime value)
///     - pointer
///     - structure (up to 8 bytes)
/// `value` is automatically casted to an appropriate-width integer.
/// If the operation fails, an error is returned.
pub fn vmwrite(field: anytype, value: anytype) VmxError!void {
    const value_int = switch (@typeInfo(@TypeOf(value))) {
        .Int, .ComptimeInt => @as(u64, value),
        .Struct => switch (@sizeOf(@TypeOf(value))) {
            1 => @as(u8, @bitCast(value)),
            2 => @as(u16, @bitCast(value)),
            4 => @as(u32, @bitCast(value)),
            8 => @as(u64, @bitCast(value)),
            else => @compileError("Unsupported structure size for vmwrite"),
        },
        .Pointer => @as(u64, @intFromPtr(value)),
        else => @compileError("Unsupported type for vmwrite"),
    };

    const rflags = asm volatile (
        \\vmwrite %[value], %[field]
        \\pushf
        \\popq %[rflags]
        : [rflags] "=r" (-> u64),
        : [field] "r" (@as(u64, @intFromEnum(field))),
          [value] "r" (@as(u64, value_int)),
    );
    try vmxtry(rflags);
}

/// Access rights of segments that can be set in guest-state area.
pub const SegmentRights = packed struct(u32) {
    const gdt = @import("../gdt.zig");

    /// Segment is accessed.
    accessed: bool = true,
    /// Readable / Writable.
    rw: bool,
    /// Direction / Conforming.
    dc: bool,
    /// Executable.
    executable: bool,
    /// Descriptor type.
    desc_type: gdt.DescriptorType,
    /// Descriptor privilege level.
    dpl: u2,
    /// Present.
    present: bool = true,
    /// Reserved.
    _reserved1: u4 = 0,
    /// Available for use by system software.
    avl: bool = false,
    /// Long mode.
    long: bool = false,
    /// Size flag.
    db: u1,
    /// Granularity.
    granularity: gdt.Granularity,
    /// Unusable.
    unusable: bool = false,
    /// Reserved.
    _reserved2: u15 = 0,

    pub fn from(val: anytype) SegmentRights {
        return @bitCast(@as(u32, @truncate(val)));
    }
};
