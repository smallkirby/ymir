//! Surtr: The bootloader for Ymir.
//!
//! Surtr is a simple bootloader that runs on UEFI firmware.
//! Most of this file is based on programs listed in "Reference".
//!
//! Reference:
//! - https://github.com/ssstoyama/bootloader_zig : Unlicense

const std = @import("std");
const uefi = std.os.uefi;
const elf = std.elf;
const log = std.log.scoped(.surtr);

pub fn main() uefi.Status {
    while (true) asm volatile ("hlt");

    return .success;
}
