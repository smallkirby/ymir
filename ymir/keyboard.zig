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
    if (parser.feed(arch.pic.ps2ReadScanCode())) |key| {
        if (key.op == .Press) {
            // Do something with the key.
        }
    }
    arch.pic.notifyEoi(.Keyboard);
}

/// Set 1 "XT" scan code.
const ScancodeParser = struct {
    const Self = @This();

    pub const Key = struct {
        /// ASCII character.
        char: u8,
        /// Operation.
        op: enum {
            /// Press.
            Press,
            /// Release.
            Release,
        },
    };

    /// Shift key state.
    shift: bool = false,
    /// Control key state.
    ctrl: bool = false,
    /// Alt key state.
    alt: bool = false,

    /// Feed a scan code and return the corresponding ASCII character.
    /// If the given scan code is a prefix, it returns null.
    pub fn feed(self: *Self, code: u8) ?Key {
        const char: ?u8 = switch (code) {
            // Press
            0x01 => '\x1B', // escape
            0x02 => '1',
            0x03 => '2',
            0x04 => '3',
            0x05 => '4',
            0x06 => '5',
            0x07 => '6',
            0x08 => '7',
            0x09 => '8',
            0x0A => '9',
            0x0B => '0',
            0x0C => '-',
            0x0D => '=',
            0x0E => '\x08', // backspace
            0x0F => '\t', // tab
            0x10 => 'q',
            0x11 => 'w',
            0x12 => 'e',
            0x13 => 'r',
            0x14 => 't',
            0x15 => 'y',
            0x16 => 'u',
            0x17 => 'i',
            0x18 => 'o',
            0x19 => 'p',
            0x1A => '[',
            0x1B => ']',
            0x1C => '\n', // enter
            0x1D => b: {
                self.ctrl = true;
                break :b null;
            },
            0x1E => 'a',
            0x1F => 's',
            0x20 => 'd',
            0x21 => 'f',
            0x22 => 'g',
            0x23 => 'h',
            0x24 => 'j',
            0x25 => 'k',
            0x26 => 'l',
            0x27 => ';',
            0x28 => '\'',
            0x29 => '`',
            0x2A => b: {
                self.shift = true;
                break :b null;
            },
            0x2B => '\\',
            0x2C => 'z',
            0x2D => 'x',
            0x2E => 'c',
            0x2F => 'v',
            0x30 => 'b',
            0x31 => 'n',
            0x32 => 'm',
            0x33 => ',',
            0x34 => '.',
            0x35 => '/',
            0x36 => b: {
                self.shift = true;
                break :b null;
            },
            0x37 => '*', // numpad
            0x38 => b: {
                self.alt = true;
                break :b null;
            },
            0x39 => ' ',
            0x3A => null, // TODO: caps lock
            0x3B => null, // TODO: F1
            0x3C => null, // TODO: F2
            0x3D => null, // TODO: F3
            0x3E => null, // TODO: F4
            0x3F => null, // TODO: F5
            0x40 => null, // TODO: F6
            0x41 => null, // TODO: F7
            0x42 => null, // TODO: F8
            0x43 => null, // TODO: F9
            0x44 => null, // TODO: F10
            0x45 => null, // TODO: num lock
            0x46 => null, // TODO: scroll lock
            0x47 => '7', // numpad
            0x48 => '8', // numpad
            0x49 => '9', // numpad
            0x4A => '-', // numpad
            0x4B => '4', // numpad
            0x4C => '5', // numpad
            0x4D => '6', // numpad
            0x4E => '+', // numpad
            0x4F => '1', // numpad
            0x50 => '2', // numpad
            0x51 => '3', // numpad
            0x52 => '0', // numpad
            0x53 => '.', // numpad
            0x57 => null, // TODO: F11
            0x58 => null, // TODO: F12

            // Release
            0x81 => '\x1B', // escape
            0x82 => '1',
            0x83 => '2',
            0x84 => '3',
            0x85 => '4',
            0x86 => '5',
            0x87 => '6',
            0x88 => '7',
            0x89 => '8',
            0x8A => '9',
            0x8B => '0',
            0x8C => '-',
            0x8D => '=',
            0x8E => '\x08', // backspace
            0x8F => '\t', // tab
            0x90 => 'q',
            0x91 => 'w',
            0x92 => 'e',
            0x93 => 'r',
            0x94 => 't',
            0x95 => 'y',
            0x96 => 'u',
            0x97 => 'i',
            0x98 => 'o',
            0x99 => 'p',
            0x9A => '[',
            0x9B => ']',
            0x9C => '\n', // enter
            0x9D => b: {
                self.ctrl = false;
                break :b null;
            },
            0x9E => 'a',
            0x9F => 's',
            0xA0 => 'd',
            0xA1 => 'f',
            0xA2 => 'g',
            0xA3 => 'h',
            0xA4 => 'j',
            0xA5 => 'k',
            0xA6 => 'l',
            0xA7 => ';',
            0xA8 => '\'',
            0xA9 => '`',
            0xAA => b: {
                self.shift = false;
                break :b null;
            },
            0xAB => '\\',
            0xAC => 'z',
            0xAD => 'x',
            0xAE => 'c',
            0xAF => 'v',
            0xB0 => 'b',
            0xB1 => 'n',
            0xB2 => 'm',
            0xB3 => ',',
            0xB4 => '.',
            0xB5 => '/',
            0xB6 => b: {
                self.shift = false;
                break :b null;
            },
            0xB7 => '*', // numpad
            0xB8 => b: {
                self.alt = false;
                break :b null;
            },
            0xB9 => ' ',
            0xBA => null, // TODO: caps lock
            0xBB => null, // TODO: F1
            0xBC => null, // TODO: F2
            0xBD => null, // TODO: F3
            0xBE => null, // TODO: F4
            0xBF => null, // TODO: F5
            0xC0 => null, // TODO: F6
            0xC1 => null, // TODO: F7
            0xC2 => null, // TODO: F8
            0xC3 => null, // TODO: F9
            0xC4 => null, // TODO: F10
            0xC5 => null, // TODO: num lock
            0xC6 => null, // TODO: scroll lock
            0xC7 => '7', // numpad
            0xC8 => '8', // numpad
            0xC9 => '9', // numpad
            0xCA => '-', // numpad
            0xCB => '4', // numpad
            0xCC => '5', // numpad
            0xCD => '6', // numpad
            0xCE => '+', // numpad
            0xCF => '1', // numpad
            0xD0 => '2', // numpad
            0xD1 => '3', // numpad
            0xD2 => '0', // numpad
            0xD3 => '.', // numpad
            0xD7 => null, // TODO: F11
            0xD8 => null, // TODO: F12

            else => null, // unimplemented
        };

        if (char) |c| {
            const modified_c = if (self.shift) b: {
                if ('a' <= c and c <= 'z') break :b c - 'a' + 'A';
                break :b switch (c) {
                    '1' => '!',
                    '2' => '@',
                    '3' => '#',
                    '4' => '$',
                    '5' => '%',
                    '6' => '^',
                    '7' => '&',
                    '8' => '*',
                    '9' => '(',
                    '0' => ')',
                    '-' => '_',
                    '=' => '+',
                    '[' => '{',
                    ']' => '}',
                    ';' => ':',
                    '\'' => '"',
                    '`' => '~',
                    '\\' => '|',
                    ',' => '<',
                    '.' => '>',
                    '/' => '?',
                    else => c,
                };
            } else c;
            return Key{
                .char = modified_c,
                .op = if (code <= 0x80) .Press else .Release,
            };
        } else return null;
    }
};
