//! This module provides a serial interface.

const std = @import("std");

const ymir = @import("ymir");
const spin = ymir.spin;
const arch = ymir.arch;

/// Spin lock for the serial console.
var spin_lock: spin.SpinLock = spin.SpinLock{};

/// Serial console.
pub const Serial = struct {
    const writeFn = *const fn (u8) void;

    /// Pointer to the arch-specific write-function.
    /// Do NOT access this field directly, use the `write` function instead.
    _write_fn: writeFn = undefined,

    const Self = @This();

    /// Write a single byte to the serial console.
    pub fn write(self: Self, c: u8) void {
        spin_lock.lockDisableIrq();
        defer spin_lock.unlockEnableIrq();
        self._write_fn(c);
    }

    fn write_unlocked(self: Self, c: u8) void {
        self._write_fn(c);
    }

    /// Write a string to the serial console.
    pub fn write_string(self: Self, s: []const u8) void {
        spin_lock.lockDisableIrq();
        defer spin_lock.unlockEnableIrq();
        for (s) |c| {
            self.write_unlocked(c);
        }
    }
};

/// Initialize the serial console.
/// You MUST call this function before using the serial console.
pub fn init() Serial {
    var serial = Serial{};
    arch.serial.initSerial(&serial, .COM1, 9600);

    return serial;
}

/// Get the serial console.
/// You MUST call `init` before calling this function.
pub fn get() Serial {
    var serial = Serial{};
    arch.serial.getSerial(&serial, .COM1);

    return serial;
}
