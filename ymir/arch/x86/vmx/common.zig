const arch = @import("arch.zig");
const vmcs = @import("vmcs.zig");

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
    /// The page is already mapped.
    AlreadyMapped,
};

/// Read RFLAGS and checks if a VMX instruction has failed.
pub fn vmxtry(rflags: u64) VmxError!void {
    const flags: arch.am.FlagsRegister = @bitCast(rflags);
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

/// Reason of failures of VMX instructions.
/// This is not updated on VM-exit.
/// cf. SDM Vol.3C 31.4.
pub const InstructionError = enum(u32) {
    error_not_available = 0,
    vmcall_in_vmxroot = 1,
    vmclear_invalid_phys = 2,
    vmclear_vmxonptr = 3,
    vmlaunch_nonclear_vmcs = 4,
    vmresume_nonlaunched_vmcs = 5,
    vmresume_after_vmxoff = 6,
    vmentry_invalid_ctrl = 7,
    vmentry_invalid_host_state = 8,
    vmptrld_invalid_phys = 9,
    vmptrld_vmxonp = 10,
    vmptrld_incorrect_rev = 11,
    vmrw_unsupported_component = 12,
    vmw_ro_component = 13,
    vmxon_in_vmxroot = 15,
    vmentry_invalid_exec_ctrl = 16,
    vmentry_nonlaunched_exec_ctrl = 17,
    vmentry_exec_vmcsptr = 18,
    vmcall_nonclear_vmcs = 19,
    vmcall_invalid_exitctl = 20,
    vmcall_incorrect_msgrev = 22,
    vmxoff_dualmonitor = 23,
    vmcall_invalid_smm = 24,
    vmentry_invalid_execctrl = 25,
    vmentry_events_blocked = 26,
    invalid_invept = 28,

    /// Get a instruction error number from VMCS.
    pub fn load() VmxError!InstructionError {
        return @enumFromInt(@as(u32, @truncate(try vmread(vmcs.ro.vminstruction_error))));
    }
};
