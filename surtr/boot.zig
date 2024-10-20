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

const blog = @import("log.zig");
const arch = @import("arch.zig");

// Override the default log options
pub const std_options = blog.default_log_options;

pub fn main() uefi.Status {
    var status: uefi.Status = undefined;

    // Initialize log.
    const con_out = uefi.system_table.con_out orelse return .Aborted;
    status = con_out.clearScreen();

    blog.init(con_out);
    log.info("Initialized bootloader log.", .{});

    // Get boot services.
    const boot_service: *uefi.tables.BootServices = uefi.system_table.boot_services orelse {
        log.err("Failed to get boot services.", .{});
        return .Aborted;
    };
    log.info("Got boot services.", .{});

    // Locate simple file system protocol.
    var fs: *uefi.protocol.SimpleFileSystem = undefined;
    status = boot_service.locateProtocol(&uefi.protocol.SimpleFileSystem.guid, null, @ptrCast(&fs));
    if (status != .Success) {
        log.err("Failed to locate simple file system protocol.", .{});
        return status;
    }
    log.info("Located simple file system protocol.", .{});

    // Open volume.
    var root_dir: *uefi.protocol.File = undefined;
    status = fs.openVolume(&root_dir);
    if (status != .Success) {
        log.err("Failed to open volume.", .{});
        return status;
    }
    log.info("Opened filesystem volume.", .{});

    // Read kernel ELF header
    const kernel = openFile(root_dir, "ymir.elf") catch return .Aborted;
    log.info("Opened kernel file.", .{});

    // Read kernel ELF header
    var header_size: usize = @sizeOf(elf.Elf64_Ehdr);
    var header_buffer: [*]align(8) u8 = undefined;
    status = boot_service.allocatePool(.LoaderData, header_size, &header_buffer);
    if (status != .Success) {
        log.err("Failed to allocate memory for kernel ELF header.", .{});
        return status;
    }

    status = kernel.read(&header_size, header_buffer);
    if (status != .Success) {
        log.err("Failed to read kernel ELF header.", .{});
        return status;
    }

    const elf_header = elf.Header.parse(header_buffer[0..@sizeOf(elf.Elf64_Ehdr)]) catch |err| {
        log.err("Failed to parse kernel ELF header: {?}", .{err});
        return .Aborted;
    };
    log.info("Parsed kernel ELF header.", .{});
    log.debug(
        \\Kernel ELF information:
        \\  Entry Point         : 0x{X}
        \\  Is 64-bit           : {d}
        \\  # of Program Headers: {d}
        \\  # of Section Headers: {d}
    ,
        .{
            elf_header.entry,
            @intFromBool(elf_header.is_64),
            elf_header.phnum,
            elf_header.shnum,
        },
    );

    // Map memory for kernel image.
    arch.page.setLv4Writable(boot_service) catch |err| {
        log.err("Failed to set page table writable: {?}", .{err});
        return .LoadError;
    };
    log.debug("Set page table writable.", .{});

    while (true) asm volatile ("hlt");

    return .success;
}

/// Convert ASCII string to UCS-2 string.
inline fn toUcs2(comptime s: [:0]const u8) [s.len * 2:0]u16 {
    var ucs2: [s.len * 2:0]u16 = [_:0]u16{0} ** (s.len * 2);
    for (s, 0..) |c, i| {
        ucs2[i] = c;
        ucs2[i + 1] = 0;
    }
    return ucs2;
}

/// Open a file using Simple File System protocol.
fn openFile(
    root: *uefi.protocol.File,
    comptime name: [:0]const u8,
) !*uefi.protocol.File {
    var file: *uefi.protocol.File = undefined;
    const status = root.open(
        &file,
        &toUcs2(name),
        uefi.protocol.File.efi_file_mode_read,
        0,
    );

    if (status != .Success) {
        log.err("Failed to open file: {s}", .{name});
        return error.Aborted;
    }
    return file;
}
