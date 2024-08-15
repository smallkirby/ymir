//! Surtr: The bootloader for Ymir.
//!
//! Surtr is a simple bootloader that runs on UEFI firmware.
//! Most of this file is based on programs listed in "Reference".
//!
//! Reference:
//! - https://github.com/ssstoyama/bootloader_zig : Unlicense
//!

const std = @import("std");
const uefi = std.os.uefi;
const elf = std.elf;
const log = std.log.scoped(.surtr);

const blog = @import("log.zig");
const defs = @import("defs.zig");
const arch = @import("arch.zig").impl;

// Override the default log options
pub const std_options = blog.default_log_options;

// Bootloader entry point.
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

    // Open kernel file.
    var kernel: *uefi.protocol.File = undefined;
    status = root_dir.open(
        &kernel,
        &toUcs2("ymir.elf"),
        uefi.protocol.File.efi_file_mode_read,
        uefi.protocol.File.efi_file_read_only,
    );
    if (status != .Success) {
        log.err("Failed to open kernel file.", .{});
        return status;
    }
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

    // Calculate necessary memory size for kernel image.
    var kernel_start_virt: elf.Elf64_Addr = std.math.maxInt(elf.Elf64_Addr);
    var kernel_start: elf.Elf64_Addr align(4096) = std.math.maxInt(elf.Elf64_Addr);
    var kernel_end: elf.Elf64_Addr = 0;
    var iter = elf_header.program_header_iterator(kernel);
    while (true) {
        const phdr = iter.next() catch |err| {
            log.err("Failed to get program header: {?}\n", .{err});
            return .LoadError;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;
        if (phdr.p_paddr < kernel_start) kernel_start = phdr.p_paddr;
        if (phdr.p_vaddr < kernel_start_virt) kernel_start_virt = phdr.p_vaddr;
        if (phdr.p_paddr + phdr.p_memsz > kernel_end) kernel_end = phdr.p_paddr + phdr.p_memsz;
    }
    const pages_4kib = (kernel_end - kernel_start + 4095) / 4096;
    log.info("Kernel image: 0x{X:0>16} - 0x{X:0>16} (0x{X} pages)", .{ kernel_start, kernel_end, pages_4kib });

    // Allocate memory for kernel image.
    status = boot_service.allocatePages(.AllocateAddress, .LoaderData, pages_4kib, @ptrCast(&kernel_start));
    if (status != .Success) {
        log.err("Failed to allocate memory for kernel image: {?}", .{status});
        return status;
    }
    log.info("Allocated memory for kernel image @ 0x{X:0>16} ~ 0x{X:0>16}", .{ kernel_start, kernel_start + pages_4kib * 4096 });

    // Map memory for kernel image
    arch.page.setLv4PageTableWritable(boot_service) catch |err| {
        log.err("Failed to set page table writable: {?}", .{err});
        return .LoadError;
    };
    log.debug("Set page table writable.", .{});

    for (0..pages_4kib) |i| {
        arch.page.mapTo(
            kernel_start_virt + 4096 * i,
            kernel_start + 4096 * i,
            .ReadWrite,
            boot_service,
        ) catch |err| {
            log.err("Failed to map memory for kernel image: {?}", .{err});
            return .LoadError;
        };
    }
    log.info("Mapped memory for kernel image.", .{});

    // Load kernel image.
    log.info("Loading kernel image...", .{});
    iter = elf_header.program_header_iterator(kernel);
    while (true) {
        const phdr = iter.next() catch |err| {
            log.err("Failed to get program header: {?}\n", .{err});
            return .LoadError;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;

        // Load data
        status = kernel.setPosition(phdr.p_offset);
        if (status != .Success) {
            log.err("Failed to set position for kernel image.", .{});
            return status;
        }
        const segment: [*]u8 = @ptrFromInt(phdr.p_vaddr);
        var mem_size = phdr.p_memsz;
        status = kernel.read(&mem_size, segment);
        if (status != .Success) {
            log.err("Failed to read kernel image.", .{});
            return status;
        }
        const chr_x: u8 = if (phdr.p_flags & elf.PF_X != 0) 'X' else '-';
        const chr_w: u8 = if (phdr.p_flags & elf.PF_W != 0) 'W' else '-';
        const chr_r: u8 = if (phdr.p_flags & elf.PF_R != 0) 'R' else '-';
        log.info(
            "  Seg @ 0x{X:0>16} - 0x{X:0>16} [{c}{c}{c}]",
            .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz, chr_x, chr_w, chr_r },
        );

        // Zero out the BSS section and uninitialized data.
        const zero_count = phdr.p_memsz - phdr.p_filesz;
        if (zero_count > 0) {
            boot_service.setMem(@ptrFromInt(phdr.p_vaddr + phdr.p_filesz), zero_count, 0);
        }

        // Change memory protection.
        const page_start = phdr.p_vaddr & ~(@as(u64, 0xFFF));
        const page_end = (phdr.p_vaddr + phdr.p_memsz + 0xFFF) & ~(@as(u64, 0xFFF));
        const size = (page_end - page_start) / 4096;
        for (0..size) |i| {
            arch.page.changeMap(
                page_start + 4096 * i,
                if (phdr.p_flags & elf.PF_W != 0) .ReadWrite else .ReadOnly,
            ) catch |err| {
                log.err("Failed to change memory protection: {?}", .{err});
                return .LoadError;
            };
        }
    }

    // Clean up memory.
    status = boot_service.freePool(header_buffer);
    if (status != .Success) {
        log.err("Failed to free memory for kernel ELF header.", .{});
        return status;
    }
    status = kernel.close();
    if (status != .Success) {
        log.err("Failed to close kernel file.", .{});
        return status;
    }
    status = root_dir.close();
    if (status != .Success) {
        log.err("Failed to close filesystem volume.", .{});
        return status;
    }

    // Exit boot services.
    // After this point, we can't use any boot services including logging.
    log.info("Exiting boot services.", .{});
    const map_buffer_size = 4096 * 4;
    var map_buffer: [map_buffer_size]u8 = undefined;
    var map = defs.MemoryMap{
        .buffer_size = map_buffer.len,
        .descriptors = @alignCast(@ptrCast(&map_buffer)),
        .map_key = 0,
        .map_size = map_buffer.len,
        .descriptor_size = 0,
        .descriptor_version = 0,
    };
    status = getMemoryMap(&map, boot_service);
    if (status != .Success) {
        log.err("Failed to get memory map.", .{});
        return status;
    }

    // Print memory map.
    log.debug("Memory Map (Physical): Buf=0x{X}, MapSize=0x{X}, DescSize=0x{X}", .{
        @intFromPtr(map.descriptors),
        map.map_size,
        map.descriptor_size,
    });
    var map_iter = defs.MemoryDescriptorIterator.new(map);
    while (true) {
        if (map_iter.next()) |md| {
            log.debug("  0x{X:0>16} - 0x{X:0>16} : {s}", .{
                md.physical_start,
                md.physical_start + md.number_of_pages * 4096,
                @tagName(md.type),
            });
        } else break;
    }

    status = boot_service.exitBootServices(uefi.handle, map.map_key);
    if (status != .Success) {
        // May fail if the memory map has been changed.
        // Retry after getting the memory map again.
        map.buffer_size = map_buffer.len;
        map.map_size = map_buffer.len;
        status = getMemoryMap(&map, boot_service);
        if (status != .Success) {
            log.err("Failed to get memory map after failed to exit boot services.", .{});
            return status;
        }
        status = boot_service.exitBootServices(uefi.handle, map.map_key);
        if (status != .Success) {
            log.err("Failed to exit boot services.", .{});
            return status;
        }
    }

    // Jump to kernel entry point.
    const KernelEntryType = fn (defs.BootInfo) callconv(.Win64) noreturn;
    const kernel_entry: *KernelEntryType = @ptrFromInt(elf_header.entry);
    const boot_info = defs.BootInfo{
        .magic = defs.surtr_magic,
        .memory_map = map,
    };
    kernel_entry(boot_info);

    unreachable;
}

inline fn toUcs2(comptime s: [:0]const u8) [s.len * 2:0]u16 {
    var ucs2: [s.len * 2:0]u16 = [_:0]u16{0} ** (s.len * 2);
    for (s, 0..) |c, i| {
        ucs2[i] = c;
        ucs2[i + 1] = 0;
    }
    return ucs2;
}

fn getMemoryMap(map: *defs.MemoryMap, boot_services: *uefi.tables.BootServices) uefi.Status {
    return boot_services.getMemoryMap(
        &map.map_size,
        map.descriptors,
        &map.map_key,
        &map.descriptor_size,
        &map.descriptor_version,
    );
}

fn halt() void {
    asm volatile ("hlt");
}
