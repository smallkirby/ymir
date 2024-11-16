const ymir = @import("ymir");
const arch = ymir.arch;

/// Serial console.
pub const Serial = struct {
    const WriteFn = *const fn (u8) void;
    const ReadFn = *const fn () ?u8;

    /// Pointer to the arch-specific write-function.
    /// Do NOT access this field directly, use the `write` function instead.
    _write_fn: WriteFn = undefined,
    /// Pointer to the arch-specific read-function.
    /// Do NOT access this field directly, use the `read` function instead.
    _read_fn: ReadFn = undefined,

    const Self = @This();

    /// Write a single byte to the serial console.
    pub fn write(self: Self, c: u8) void {
        self._write_fn(c);
    }

    /// Write a string to the serial console.
    pub fn writeString(self: Self, s: []const u8) void {
        for (s) |c| {
            self.write(c);
        }
    }

    /// Try to read a character from the serial console.
    /// Returns null if no character is available in Rx-buffer.
    pub fn tryRead(self: Self) ?u8 {
        return self._read_fn();
    }
};

/// Initialize the serial console.
/// You MUST call this function before using the serial console.
pub fn init() Serial {
    var serial = Serial{};
    arch.serial.initSerial(&serial, .com1, 115200);

    return serial;
}

/// Get the serial console.
/// You MUST call `init` before calling this function.
pub fn get() Serial {
    var serial = Serial{};
    arch.serial.getSerial(&serial, .com1);

    return serial;
}
