//! Surtr: The bootloader for Ymir.
//!
//! Surtr is a simple bootloader that runs on UEFI firmware.
//! Most of this file is based on programs listed in "Reference".
//!
//! Reference:
//! - https://github.com/ssstoyama/bootloader_zig : Unlicense
//!

const std = @import("std");
const atomic = std.atomic;
const uefi = std.os.uefi;
const elf = std.elf;
const log = std.log.scoped(.surtr);

const blog = @import("log.zig");
const defs = @import("defs.zig");
const arch = @import("arch.zig");
const mp = @import("mp.zig");
const spin = @import("spin.zig");

const page_size = arch.page.page_size_4k;
const page_mask = arch.page.page_mask_4k;

// Override the default log options
pub const std_options = blog.default_log_options;

var lock = spin.SpinLock{};
var num_ap_started = atomic.Value(usize).init(0);

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

    // Calculate necessary memory size for kernel image.
    const Addr = elf.Elf64_Addr;
    var kernel_start_virt: Addr = std.math.maxInt(Addr);
    var kernel_start_phys: Addr align(page_size) = std.math.maxInt(Addr);
    var kernel_end_phys: Addr = 0;
    var iter = elf_header.program_header_iterator(kernel);
    while (true) {
        const phdr = iter.next() catch |err| {
            log.err("Failed to get program header: {?}\n", .{err});
            return .LoadError;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;
        if (phdr.p_paddr < kernel_start_phys) kernel_start_phys = phdr.p_paddr;
        if (phdr.p_vaddr < kernel_start_virt) kernel_start_virt = phdr.p_vaddr;
        if (phdr.p_paddr + phdr.p_memsz > kernel_end_phys) kernel_end_phys = phdr.p_paddr + phdr.p_memsz;
    }
    const pages_4kib = (kernel_end_phys - kernel_start_phys + (page_size - 1)) / page_size;
    log.info("Kernel image: 0x{X:0>16} - 0x{X:0>16} (0x{X} pages)", .{ kernel_start_phys, kernel_end_phys, pages_4kib });

    // Allocate memory for kernel image.
    status = boot_service.allocatePages(.AllocateAddress, .LoaderData, pages_4kib, @ptrCast(&kernel_start_phys));
    if (status != .Success) {
        log.err("Failed to allocate memory for kernel image: {?}", .{status});
        return status;
    }
    log.info("Allocated memory for kernel image @ 0x{X:0>16} ~ 0x{X:0>16}", .{ kernel_start_phys, kernel_start_phys + pages_4kib * page_size });

    // Map memory for kernel image.
    arch.page.setLv4Writable(boot_service) catch |err| {
        log.err("Failed to set page table writable: {?}", .{err});
        return .LoadError;
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
                log.err("Failed to change meggmory protection: {?}", .{err});
                return .LoadError;
            };
        }
    }

    // Enable NX-bit.
    arch.enableNxBit();

    // Get guest kernel image info.
    const guest = openFile(root_dir, "bzImage") catch return .Aborted;
    log.info("Opened guest kernel file.", .{});

    const guest_info_buffer_size: usize = @sizeOf(uefi.FileInfo) + 0x100;
    var guest_info_actual_size = guest_info_buffer_size;
    var guest_info_buffer: [guest_info_buffer_size]u8 align(@alignOf(uefi.FileInfo)) = undefined;
    status = guest.getInfo(&uefi.FileInfo.guid, &guest_info_actual_size, &guest_info_buffer);
    if (status != .Success) {
        log.err("Failed to get guest kernel file info.", .{});
        return status;
    }
    const guest_info: *const uefi.FileInfo = @alignCast(@ptrCast(&guest_info_buffer));
    log.info("Guest kernel size: {X} bytes", .{guest_info.file_size});

    // Load guest kernel image.
    var guest_start: u64 align(page_size) = undefined;
    const guest_size_pages = (guest_info.file_size + (page_size - 1)) / page_size;
    status = boot_service.allocatePages(.AllocateAnyPages, .LoaderData, guest_size_pages, @ptrCast(&guest_start));
    if (status != .Success) {
        log.err("Failed to allocate memory for guest kernel image.", .{});
        return status;
    }
    var guest_size = guest_info.file_size;

    status = guest.read(&guest_size, @ptrFromInt(guest_start));
    if (status != .Success) {
        log.err("Failed to read guest kernel image.", .{});
        return status;
    }
    log.info("Loaded guest kernel image @ 0x{X:0>16} ~ 0x{X:0>16}", .{ guest_start, guest_start + guest_size });

    // Load initrd.
    const initrd = openFile(root_dir, "rootfs.cpio.gz") catch return .Aborted;
    log.info("Opened initrd file.", .{});

    const initrd_info_buffer_size: usize = @sizeOf(uefi.FileInfo) + 0x100;
    var initrd_info_actual_size = initrd_info_buffer_size;
    var initrd_info_buffer: [initrd_info_buffer_size]u8 align(@alignOf(uefi.FileInfo)) = undefined;
    status = initrd.getInfo(&uefi.FileInfo.guid, &initrd_info_actual_size, &initrd_info_buffer);
    if (status != .Success) {
        log.err("Failed to get initrd file info.", .{});
        return status;
    }
    const initrd_info: *const uefi.FileInfo = @alignCast(@ptrCast(&initrd_info_buffer));
    var initrd_size = initrd_info.file_size;
    log.info("Initrd size: 0x{X:0>16} bytes", .{initrd_size});

    var initrd_start: u64 = undefined;
    const initrd_size_pages = (initrd_size + (page_size - 1)) / page_size;
    status = boot_service.allocatePages(.AllocateAnyPages, .LoaderData, initrd_size_pages, @ptrCast(&initrd_start));
    if (status != .Success) {
        log.err("Failed to allocate memory for initrd.", .{});
        return status;
    }

    status = initrd.read(&initrd_size, @ptrFromInt(initrd_start));
    if (status != .Success) {
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
        return .LoadError;
    };
    log.info("ACPI table @ 0x{X:0>16}", .{@intFromPtr(acpi_table)});

    // Clean up memory.
    status = boot_service.freePool(header_buffer);
    if (status != .Success) {
        log.err("Failed to free memory for kernel ELF header.", .{});
        return status;
    }
    status = initrd.close();
    if (status != .Success) {
        log.err("Failed to close initrd file.", .{});
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

    // Get MP Services protocol.
    var mps: *mp.MpService = undefined;
    status = boot_service.locateProtocol(&mp.MpService.guid, null, @ptrCast(&mps));
    if (status != .Success) {
        log.err("Failed to locate MP Services protocol.", .{});
        return status;
    }
    log.info("Located MP Services protocol.", .{});

    // Get the number of processors.
    var num_proc: u64 = undefined;
    var num_enabled_proc: u64 = undefined;
    status = mps.getNumberOfProcessors(&num_proc, &num_enabled_proc);
    if (status != .Success) {
        log.err("Failed to get number of processors.", .{});
        return status;
    }
    log.info("Number of processors: {d} (enabled: {d})", .{ num_proc, num_enabled_proc });

    status = mps.whoAmI(&num_proc);
    if (status != .Success) {
        log.err("Failed to get processor ID.", .{});
        return status;
    }
    log.info("BSP ID: {d}", .{num_proc});

    // Start APs.
    const kernel_entry: *KernelEntryType = @ptrFromInt(elf_header.entry);
    var boot_info = defs.BootInfo{
        .magic = defs.magic,
        .memory_map = undefined,
        .guest_info = .{
            .guest_image = @ptrFromInt(guest_start),
            .guest_size = guest_size,
            .initrd_addr = @ptrFromInt(initrd_start),
            .initrd_size = initrd_info.file_size,
        },
        .acpi_table = acpi_table,
        .num_cpus = num_proc,
        .stack_top = undefined,
        .stack_size = undefined,
    };

    var ap_arg = ApArg{
        .mps = mps,
        .bs = boot_service,
        .boot_info = boot_info,
        .kernel_entry = kernel_entry,
    };
    status = mps.startupAllAps(
        apMain,
        false,
        null,
        1000 * 1000, // 3sec // TODO
        &ap_arg,
        null,
    );
    while (num_ap_started.load(.acquire) < num_enabled_proc - 1) {
        atomic.spinLoopHint();
    }
    log.info("All APs started.", .{});

    // Allocate memory for BSP.
    const stack_size = 5 * page_size;
    var stack_top: u64 = undefined;
    status = boot_service.allocatePages(.AllocateAnyPages, .LoaderData, stack_size / page_size, @ptrCast(&stack_top));
    if (status != .Success) {
        log.err("Failed to allocate stack for BSP.", .{});
        return status;
    }
    log.debug("Allocated stack for BSP @ 0x{X:0>16}", .{stack_top});

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
                md.physical_start + md.number_of_pages * page_size,
                @tagName(md.type),
            });
        } else break;
    }

    // Exit boot services.
    // After this point, we can't use any boot services including logging.
    log.info("Exiting boot services.", .{});
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
    boot_info.memory_map = map;
    boot_info.stack_size = stack_size;
    boot_info.stack_top = @ptrFromInt(stack_top);
    const stack = @intFromPtr(boot_info.stack_top) + stack_size - 0x10;
    asm volatile (
        \\movq %[boot_info], %%rdi
        \\movq %[rsp], %%rsp
        \\call *%[kernel_entry]
        :
        : [boot_info] "r" (&boot_info),
          [rsp] "r" (stack),
          [kernel_entry] "r" (kernel_entry),
    );

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

const KernelEntryType = fn (defs.BootInfo, u64) callconv(.Win64) noreturn;

const ApArg = struct {
    mps: *mp.MpService,
    bs: *uefi.tables.BootServices,
    boot_info: defs.BootInfo,
    kernel_entry: *KernelEntryType,
};

fn apMain(arg: *anyopaque) callconv(uefi.cc) void {
    const ap_arg: *ApArg = @alignCast(@ptrCast(arg));
    const mps = ap_arg.mps;
    const bs = ap_arg.bs;

    var boot_info = ap_arg.boot_info;
    var status: uefi.Status = undefined;

    // Print AP ID.
    var id: u64 = undefined;
    lock.lock();
    {
        status = mps.whoAmI(&id);
        if (status != .Success) {
            log.err("Failed to get processor ID.", .{});
            return;
        }
        log.info("AP started: #{d}", .{id});
    }
    lock.unlock();

    // Allocate stack.
    const stack_size = 5 * page_size;
    var stack_top: u64 = undefined;
    lock.lock();
    {
        status = bs.allocatePages(.AllocateAnyPages, .LoaderData, stack_size / page_size, @ptrCast(&stack_top));
        if (status != .Success) {
            log.err("Failed to allocate stack for AP.", .{});
            return;
        }
        boot_info.stack_size = stack_size;
        boot_info.stack_top = @ptrFromInt(stack_top);
        log.debug("Allocated stack for AP#{d} @ 0x{X:0>16}", .{ id, stack_top });
    }
    lock.unlock();

    _ = num_ap_started.fetchAdd(1, .acq_rel);

    lock.lock();
    log.info("AP#{d} entering Ymir....", .{id});
    lock.unlock();

    while (true) {
        halt();
    }

    const rsp = stack_top + stack_size - 0x10;
    asm volatile (
        \\movq %[ap_arg], %%rdi
        \\movq %[new_stack], %%rsp
        \\call  *%[kernel_entry]
        :
        : [ap_arg] "r" (ap_arg),
          [new_stack] "r" (rsp),
          [kernel_entry] "r" (ap_arg.kernel_entry),
    );

    unreachable;
}
