const ymir = @import("ymir");
const phys2virt = ymir.mem.phys2virt;

/// Local APIC ID registers
const lapic_id_register: u64 = 0xFEE0_0020;
/// Local APIC version register
const lapic_version_register: u64 = 0xFEE0_0030;
/// Task Priority Register
const tpr: u64 = 0xFEE0_0080;
/// Arbitration Priority Register
const apr: u64 = 0xFEE0_0090;
/// Processor Priority Register
const ppr: u64 = 0xFEE0_00A0;
/// EOI Register
const eoi: u64 = 0xFEE0_00B0;
/// LVT (Local Vector Table) Timer Register
const lvt_timer_register: u64 = 0xFEE0_0320;
/// Initial Count Register for Timer
const initial_count_register: u64 = 0xFEE0_0380;
/// Current Count Register for Timer
const current_count_register: u64 = 0xFEE0_0390;
/// Divide Configuration Register for Timer
const divide_config_register: u64 = 0xFEE0_03E0;

/// Get a Local APIC ID of the current core.
pub fn getLapicId() u8 {
    const addr: *u32 = @ptrFromInt(phys2virt(lapic_id_register));
    return @truncate(addr.* >> 24);
}
