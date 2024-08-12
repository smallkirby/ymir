//! Legacy PS/2 keyboard.

const std = @import("std");
const log = std.log.scoped(.kbd);

const ymir = @import("ymir");
const idefs = @import("interrupts.zig");
const arch = ymir.arch;

/// PS/2 keyboard scan code parser.
var parser = ScancodeParser{};

/// Initialize PS/2 keyboard and its interrupt handler.
pub fn init() void {
    arch.pic.unsetMask(.Keyboard);
    arch.intr.registerHandler(idefs.pic_keyboard, interruptHandler);
}

fn interruptHandler(_: *arch.intr.Context) void {
    if (parser.feed(arch.pic.ps2ReadScanCode())) |_| {
        // Do something with the key.
    }
    arch.pic.notifyEoi(.Keyboard);
}

/// Set 1 "XT" scan code.
const ScancodeParser = struct {
    const Self = @This();

    const keycode_map: [256]?u8 = [_]?u8{
        // Pressed
        null, null, '1', '2', '3', '4', '5', '6', // 0x00
        '7', '8', '9', '0', '-', '=', '\x08', '\t', // 0x08
        'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', // 0x10
        'o', 'p', '[', ']', '\n', null, 'a', 's', // 0x18
        'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', // 0x20
        '\'', '`', null, '\\', 'z', 'x', 'c', 'v', // 0x28
        'b', 'n', 'm', ',', '.', '/', null, '*', // 0x30
        null, ' ', null, null, null, null, null, null, // 0x38
        null, null, null, null, null, null, null, '7', // 0x40
        '8', '9', '-', '4', '5', '6', '+', '1', // 0x48
        '2', '3', '0', '.', null, null, null, null, // 0x50
    } ++ [_]?u8{null} ** (0x28) ++ [_]?u8{
        // Released
        null, null, '1', '2', '3', '4', '5', '6', // 0x80
        '7', '8', '9', '0', '-', '=', '\x08', '\t', // 0x88
        'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', // 0x90
        'o', 'p', '[', ']', '\n', null, 'a', 's', // 0x98
        'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', // 0xA0
        '\'', '`', null, '\\', 'z', 'x', 'c', 'v', // 0xA8
        'b', 'n', 'm', ',', '.', '/', null, '*', // 0xB0
        null, ' ', null, null, null, null, null, null, // 0xB8
        null, null, null, null, null, null, null, '7', // 0xC0
        '8', '9', '-', '4', '5', '6', '+', '1', // 0xC8
        '2', '3', '0', '.', null, null, null, null, // 0xD0
    } ++ [_]?u8{null} ** (0x28);

    const shifted_keycode_map: [256]?u8 = [_]?u8{
        // Pressed
        null, null, '!', '@', '#', '$', '%', '^', // 0x00
        '&', '*', '(', ')', '_', '+', '\x08', '\t', // 0x08
        'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', // 0x10
        'O', 'P', '{', '}', '\n', null, 'A', 'S', // 0x18
        'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', // 0x20
        '"', '~', null, '|', 'Z', 'X', 'C', 'V', // 0x28
        'B', 'N', 'M', '<', '>', '?', null, '*', // 0x30
        null, ' ', null, null, null, null, null, null, // 0x38
        null, null, null, null, null, null, null, '7', // 0x40
        '8', '9', '-', '4', '5', '6', '+', '1', // 0x48
        '2', '3', '0', '.', null, null, null, null, // 0x50
    } ++ [_]?u8{null} ** (0x28) ++ [_]?u8{
        // Released
        null, null, '!', '@', '#', '$', '%', '^', // 0x80
        '&', '*', '(', ')', '_', '+', '\x08', '\t', // 0x88
        'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', // 0x90
        'O', 'P', '{', '}', '\n', null, 'A', 'S', // 0x98
        'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', // 0xA0
        '"', '~', null, '|', 'Z', 'X', 'C', 'V', // 0xA8
        'B', 'N', 'M', '<', '>', '?', null, '*', // 0xB0
        null, ' ', null, null, null, null, null, null, // 0xB8
        null, null, null, null, null, null, null, '7', // 0xC0
        '8', '9', '-', '4', '5', '6', '+', '1', // 0xC8
        '2', '3', '0', '.', null, null, null, null, // 0xD0
    } ++ [_]?u8{null} ** (0x28);

    const code_left_shift_press = 0x2A;
    const code_right_shift_press = 0x36;
    const code_left_ctrl_press = 0x1D;
    const code_right_ctrl_press = 0x1D;
    const code_left_alt_press = 0x38;
    const code_right_alt_press = 0x38;

    const code_left_shift_release = 0xAA;
    const code_right_shift_release = 0xB6;
    const code_left_ctrl_release = 0x9D;
    const code_right_ctrl_release = 0x9D;
    const code_left_alt_release = 0xB8;
    const code_right_alt_release = 0xB8;

    /// Shift key state.
    shift: bool = false,
    /// Control key state.
    ctrl: bool = false,
    /// Alt key state.
    alt: bool = false,

    /// Feed a scan code and return the corresponding ASCII character.
    /// If the given scan code is a prefix, it returns null.
    pub fn feed(self: *Self, code: u8) ?u8 {
        if (code == code_left_shift_press or code == code_right_shift_press) {
            self.shift = true;
            return null;
        }
        if (code == code_left_shift_release or code == code_right_shift_release) {
            self.shift = false;
            return null;
        }
        if (code == code_left_ctrl_press or code == code_right_ctrl_press) {
            self.ctrl = true;
            return null;
        }
        if (code == code_left_ctrl_release or code == code_right_ctrl_release) {
            self.ctrl = false;
            return null;
        }
        if (code == code_left_alt_press or code == code_right_alt_press) {
            self.alt = true;
            return null;
        }
        if (code == code_left_alt_release or code == code_right_alt_release) {
            self.alt = false;
            return null;
        }

        if (code >= 0x80) return null; // Release

        const converted = if (self.shift) shifted_keycode_map[code] else keycode_map[code];
        return converted;
    }
};
