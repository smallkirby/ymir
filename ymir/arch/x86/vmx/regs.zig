const am = @import("../asm.zig");
const vmx = @import("../vmx.zig");
const vmcs = @import("vmcs.zig");
const VmxError = vmx.VmxError;

pub const guest = struct {
    /// x64 guest registers.
    pub const Registers = struct {
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rbp: u64,
        rsp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        rflags: u64,
    };

    pub const SegRegisters = struct {
        cs: SegRegister,
        ds: SegRegister,
        es: SegRegister,
        fs: SegRegister,
        gs: SegRegister,
        ss: SegRegister,
        tr: SegRegister,
        ldt: SegRegister,
    };

    pub const ControlRegisters = struct {
        cr0: u64,
        cr3: u64,
        cr4: u64,

        pub fn load(self: ControlRegisters) VmxError!void {
            try vmcs.vmwrite(vmcs.guest_cr0, self.cr0);
            try vmcs.vmwrite(vmcs.guest_cr3, self.cr3);
            try vmcs.vmwrite(vmcs.guest_cr4, self.cr4);
        }

        pub fn get() VmxError!ControlRegisters {
            return .{
                .cr0 = try vmcs.vmread(vmcs.guest_cr0),
                .cr3 = try vmcs.vmread(vmcs.guest_cr3),
                .cr4 = try vmcs.vmread(vmcs.guest_cr4),
            };
        }
    };

    pub const SegRegister = struct {
        /// Segment base.
        base: u64,
        /// Segment limit.
        limit: u32,
        /// Segment selector.
        selector: u16,

        /// P. Present bit.
        present: bool,
        /// DPL. Descriptor privilege level.
        dpl: u2,
        /// S. Descriptor type (System or Code/Data).
        system: bool,
        /// E. Executable bit.
        executable: bool,
        /// DC. Direction bit.
        direction: Direction,
        /// RW. Read/Write bit.
        /// For code segments, false means execute-only. For data segments, false means read-only.
        rw: bool,
        /// A. Accessed bit.
        accessed: bool,

        /// G. Size granularity.
        granularity: Granularity,
        /// DB. Size flag.
        db: SizeFlag,
        /// L. Long-mode code flag.
        long: bool,

        const SizeFlag = enum(u1) {
            protected16 = 0,
            protected32 = 1,
        };

        const Direction = enum(u1) {
            up = 0,
            down = 1,
        };

        const Granularity = enum(u1) {
            byte = 0,
            page = 1,
        };
    };
};
