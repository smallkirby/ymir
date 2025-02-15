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
const arch = @import("arch.zig");

const page_size = arch.page.page_size_4k;
const page_mask = arch.page.page_mask_4k;

// Override the default log options
pub const std_options = blog.default_log_options;

// Bootloader entry point.
pub fn main() uefi.Status {
    var status: uefi.Status = undefined;

    // Initialize log.
    const con_out = uefi.system_table.con_out orelse return .aborted;
    status = con_out.clearScreen();
    blog.init(con_out);

    log.info("Initialized bootloader log.", .{});

    // Get boot services.
    const boot_service: *uefi.tables.BootServices = uefi.system_table.boot_services orelse {
        log.err("Failed to get boot services.", .{});
        return .aborted;
    };
    log.info("Got boot services.", .{});

    // Locate simple file system protocol.
    var fs: *uefi.protocol.SimpleFileSystem = undefined;
    status = boot_service.locateProtocol(&uefi.protocol.SimpleFileSystem.guid, null, @ptrCast(&fs));
    if (status != .success) {
        log.err("Failed to locate simple file system protocol.", .{});
        return status;
    }
    log.info("Located simple file system protocol.", .{});

    // Open volume.
    var root_dir: *const uefi.protocol.File = undefined;
    status = fs.openVolume(&root_dir);
    if (status != .success) {
        log.err("Failed to open volume.", .{});
        return status;
    }
    log.info("Opened filesystem volume.", .{});

    // Open kernel file.
    const kernel = openFile(root_dir, "ymir.elf") catch return .aborted;
    log.info("Opened kernel file.", .{});

    // Read kernel ELF header
    var header_size: usize = @sizeOf(elf.Elf64_Ehdr);
    var header_buffer: [*]align(8) u8 = undefined;
    status = boot_service.allocatePool(.loader_data, header_size, &header_buffer);
    if (status != .success) {
        log.err("Failed to allocate memory for kernel ELF header.", .{});
        return status;
    }

    status = kernel.read(&header_size, header_buffer);
    if (status != .success) {
        log.err("Failed to read kernel ELF header.", .{});
        return status;
    }

    const elf_header = elf.Header.parse(header_buffer[0..@sizeOf(elf.Elf64_Ehdr)]) catch |err| {
        log.err("Failed to parse kernel ELF header: {?}", .{err});
        return .aborted;
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
    const Addr = elf.Elf64_Addr;
    var kernel_start_virt: Addr = std.math.maxInt(Addr);
    var kernel_start_phys: Addr align(page_size) = std.math.maxInt(Addr);
    var kernel_end_phys: Addr = 0;
    var iter = elf_header.program_header_iterator(@constCast(kernel));
    while (true) {
        const phdr = iter.next() catch |err| {
            log.err("Failed to get program header: {?}\n", .{err});
            return .load_error;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;
        if (phdr.p_paddr < kernel_start_phys) kernel_start_phys = phdr.p_paddr;
        if (phdr.p_vaddr < kernel_start_virt) kernel_start_virt = phdr.p_vaddr;
        if (phdr.p_paddr + phdr.p_memsz > kernel_end_phys) kernel_end_phys = phdr.p_paddr + phdr.p_memsz;
    }
    const pages_4kib = (kernel_end_phys - kernel_start_phys + (page_size - 1)) / page_size;
    log.info("Kernel image: 0x{X:0>16} - 0x{X:0>16} (0x{X} pages)", .{ kernel_start_phys, kernel_end_phys, pages_4kib });

    // Allocate memory for kernel image.
    status = boot_service.allocatePages(.allocate_address, .loader_data, pages_4kib, @ptrCast(&kernel_start_phys));
    if (status != .success) {
        log.err("Failed to allocate memory for kernel image: {?}", .{status});
        return status;
    }
    log.info("Allocated memory for kernel image @ 0x{X:0>16} ~ 0x{X:0>16}", .{ kernel_start_phys, kernel_start_phys + pages_4kib * page_size });

    // Map memory for kernel image.
    arch.page.setLv4Writable(boot_service) catch |err| {
        log.err("Failed to set page table writable: {?}", .{err});
        return .load_error;
    };
    log.debug("Set page table writable.", .{});

    for (0..pages_4kib) |i| {
        arch.page.map4kTo(
            kernel_start_virt + page_size * i,
            kernel_start_phys + page_size * i,
            .read_write,
            boot_service,
        ) catch |err| {
            log.err("Failed to map memory for kernel image: {?}", .{err});
            return .load_error;
        };
    }
    log.info("Mapped memory for kernel image.", .{});

    // Load kernel image.
    log.info("Loading kernel image...", .{});
    iter = elf_header.program_header_iterator(@constCast(kernel));
    while (true) {
        const phdr = iter.next() catch |err| {
            log.err("Failed to get program header: {?}\n", .{err});
            return .load_error;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;

        // Load data
        status = kernel.setPosition(phdr.p_offset);
        if (status != .success) {
            log.err("Failed to set position for kernel image.", .{});
            return status;
        }
        const segment: [*]u8 = @ptrFromInt(phdr.p_vaddr);
        var mem_size = phdr.p_memsz;
        status = kernel.read(&mem_size, segment);
        if (status != .success) {
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

        // Zero-clear the BSS section and uninitialized data.
        const zero_count = phdr.p_memsz - phdr.p_filesz;
        if (zero_count > 0) {
            boot_service.setMem(@ptrFromInt(phdr.p_vaddr + phdr.p_filesz), zero_count, 0);
        }

        // Change memory protection.
        const page_start = phdr.p_vaddr & ~page_mask;
        const page_end = (phdr.p_vaddr + phdr.p_memsz + (page_size - 1)) & ~page_mask;
        const size = (page_end - page_start) / page_size;
        const attribute = arch.page.PageAttribute.fromFlags(phdr.p_flags);
        for (0..size) |i| {
            arch.page.changeMap4k(
                page_start + page_size * i,
                attribute,
            ) catch |err| {
                log.err("Failed to change memory protection: {?}", .{err});
                return .load_error;
            };
        }
    }

    // Enable NX-bit.
    arch.enableNxBit();

    // Get guest kernel image info.
    const guest = openFile(root_dir, "bzImage") catch return .aborted;
    log.info("Opened guest kernel file.", .{});

    const guest_info_buffer_size: usize = @sizeOf(uefi.FileInfo) + 0x100;
    var guest_info_actual_size = guest_info_buffer_size;
    var guest_info_buffer: [guest_info_buffer_size]u8 align(@alignOf(uefi.FileInfo)) = undefined;
    status = guest.getInfo(&uefi.FileInfo.guid, &guest_info_actual_size, &guest_info_buffer);
    if (status != .success) {
        log.err("Failed to get guest kernel file info.", .{});
        return status;
    }
    const guest_info: *const uefi.FileInfo = @alignCast(@ptrCast(&guest_info_buffer));
    log.info("Guest kernel size: {X} bytes", .{guest_info.file_size});

    // Load guest kernel image.
    var guest_start: u64 align(page_size) = undefined;
    const guest_size_pages = (guest_info.file_size + (page_size - 1)) / page_size;
    status = boot_service.allocatePages(.allocate_any_pages, .loader_data, guest_size_pages, @ptrCast(&guest_start));
    if (status != .success) {
        log.err("Failed to allocate memory for guest kernel image.", .{});
        return status;
    }
    var guest_size = guest_info.file_size;

    status = guest.read(&guest_size, @ptrFromInt(guest_start));
    if (status != .success) {
        log.err("Failed to read guest kernel image.", .{});
        return status;
    }
    log.info("Loaded guest kernel image @ 0x{X:0>16} ~ 0x{X:0>16}", .{ guest_start, guest_start + guest_size });

    // Load initrd.
    const initrd = openFile(root_dir, "rootfs.cpio.gz") catch return .aborted;
    log.info("Opened initrd file.", .{});

    const initrd_info_buffer_size: usize = @sizeOf(uefi.FileInfo) + 0x100;
    var initrd_info_actual_size = initrd_info_buffer_size;
    var initrd_info_buffer: [initrd_info_buffer_size]u8 align(@alignOf(uefi.FileInfo)) = undefined;
    status = initrd.getInfo(&uefi.FileInfo.guid, &initrd_info_actual_size, &initrd_info_buffer);
    if (status != .success) {
        log.err("Failed to get initrd file info.", .{});
        return status;
    }
    const initrd_info: *const uefi.FileInfo = @alignCast(@ptrCast(&initrd_info_buffer));
    var initrd_size = initrd_info.file_size;
    log.info("Initrd size: 0x{X:0>16} bytes", .{initrd_size});

    var initrd_start: u64 = undefined;
    const initrd_size_pages = (initrd_size + (page_size - 1)) / page_size;
    status = boot_service.allocatePages(.allocate_any_pages, .loader_data, initrd_size_pages, @ptrCast(&initrd_start));
    if (status != .success) {
        log.err("Failed to allocate memory for initrd.", .{});
        return status;
    }

    status = initrd.read(&initrd_size, @ptrFromInt(initrd_start));
    if (status != .success) {
        log.err("Failed to read initrd.", .{});
        return status;
    }
    log.info("Loaded initrd @ 0x{X:0>16} ~ 0x{X:0>16}", .{ initrd_start, initrd_start + initrd_size });

    // Find RSDP.
    const acpi_table_guid = uefi.Guid{
        .time_low = 0x8868E871,
        .time_mid = 0xE4F1,
        .time_high_and_version = 0x11D3,
        .clock_seq_high_and_reserved = 0xBC,
        .clock_seq_low = 0x22,
        .node = [_]u8{ 0x0, 0x80, 0xC7, 0x3C, 0x88, 0x81 },
    };
    const acpi_table = for (0..uefi.system_table.number_of_table_entries) |i| {
        const guid = uefi.system_table.configuration_table[i].vendor_guid;
        if (uefi.Guid.eql(acpi_table_guid, guid)) {
            break uefi.system_table.configuration_table[i].vendor_table;
        }
    } else {
        log.err("Failed to find ACPI table.", .{});
        return .load_error;
    };
    log.info("ACPI table @ 0x{X:0>16}", .{@intFromPtr(acpi_table)});

    // Clean up memory.
    status = boot_service.freePool(header_buffer);
    if (status != .success) {
        log.err("Failed to free memory for kernel ELF header.", .{});
        return status;
    }
    status = initrd.close();
    if (status != .success) {
        log.err("Failed to close initrd file.", .{});
        return status;
    }
    status = kernel.close();
    if (status != .success) {
        log.err("Failed to close kernel file.", .{});
        return status;
    }
    status = root_dir.close();
    if (status != .success) {
        log.err("Failed to close filesystem volume.", .{});
        return status;
    }

    // Get memory map.
    const map_buffer_size = page_size * 4;
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
    if (status != .success) {
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
                md.physical_start + md.number_of_pages * page_size,
                @tagName(md.type),
            });
        } else break;
    }

    // Exit boot services.
    // After this point, we can't use any boot services including logging.
    log.info("Exiting boot services.", .{});
    status = boot_service.exitBootServices(uefi.handle, map.map_key);
    if (status != .success) {
        // May fail if the memory map has been changed.
        // Retry after getting the memory map again.
        map.buffer_size = map_buffer.len;
        map.map_size = map_buffer.len;
        status = getMemoryMap(&map, boot_service);
        if (status != .success) {
            log.err("Failed to get memory map after failed to exit boot services.", .{});
            return status;
        }
        status = boot_service.exitBootServices(uefi.handle, map.map_key);
        if (status != .success) {
            log.err("Failed to exit boot services.", .{});
            return status;
        }
    }

    // Jump to kernel entry point.
    const KernelEntryType = fn (defs.BootInfo) callconv(.Win64) noreturn;
    const kernel_entry: *KernelEntryType = @ptrFromInt(elf_header.entry);
    const boot_info = defs.BootInfo{
        .magic = defs.magic,
        .memory_map = map,
        .guest_info = .{
            .guest_image = @ptrFromInt(guest_start),
            .guest_size = guest_size,
            .initrd_addr = @ptrFromInt(initrd_start),
            .initrd_size = initrd_info.file_size,
        },
        .acpi_table = acpi_table,
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

/// Open a file using Simple File System protocol.
fn openFile(
    root: *const uefi.protocol.File,
    comptime name: [:0]const u8,
) !*const uefi.protocol.File {
    var file: *const uefi.protocol.File = undefined;
    const status = root.open(
        &file,
        &toUcs2(name),
        uefi.protocol.File.efi_file_mode_read,
        0,
    );

    if (status != .success) {
        log.err("Failed to open file: {s}", .{name});
        return error.aborted;
    }
    return file;
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
