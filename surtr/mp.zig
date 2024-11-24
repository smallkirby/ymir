const builtin = @import("builtin");
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;

const Uintn = if (builtin.target.ptrBitWidth() == 64) u64 else @compileError("Unsupported architecture.");
const EfiApProcedure = *const fn (*anyopaque) callconv(cc) void;
const NotImplementedFn = *const fn () callconv(cc) Status;

pub const MpService = extern struct {
    const Self = @This();

    _get_number_of_processors: *const fn (*const Self, *Uintn, *Uintn) callconv(cc) Status,
    _get_processor_info: NotImplementedFn,
    _startup_all_aps: *const fn (*const Self, EfiApProcedure, bool, *allowzero anyopaque, Uintn, *allowzero anyopaque, *allowzero *Uintn) callconv(cc) Status,
    _startup_this_ap: NotImplementedFn,
    _switch_bsp: NotImplementedFn,
    _enable_disable_ap: NotImplementedFn,
    _who_am_i: *const fn (*const Self, *Uintn) callconv(cc) Status,

    pub fn getNumberOfProcessors(self: *const Self, numProc: *Uintn, numEnabledProc: *Uintn) Status {
        return self._get_number_of_processors(self, numProc, numEnabledProc);
    }

    pub fn startupAllAps(
        self: *const Self,
        procedure: EfiApProcedure,
        singleThread: bool,
        waitEvent: ?*anyopaque, // TODO
        timeoutInMicroseconds: Uintn,
        procedureArgument: ?*anyopaque,
        failedCpuList: ?**Uintn,
    ) Status {
        return self._startup_all_aps(
            self,
            procedure,
            singleThread,
            waitEvent orelse @ptrFromInt(0),
            timeoutInMicroseconds,
            procedureArgument orelse @ptrFromInt(0),
            failedCpuList orelse @ptrFromInt(0),
        );
    }

    pub fn whoAmI(self: *const Self, apicId: *Uintn) Status {
        return self._who_am_i(self, apicId);
    }

    pub const guid align(8) = Guid{
        .time_low = 0x3FDDA605,
        .time_mid = 0xa76e,
        .time_high_and_version = 0x4f46,
        .clock_seq_high_and_reserved = 0xad,
        .clock_seq_low = 0x29,
        .node = [_]u8{ 0x12, 0xF4, 0x53, 0x1B, 0x3D, 0x08 },
    };
};
