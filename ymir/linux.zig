const std = @import("std");

pub const layout = struct {
    /// Where the kernel boot parameters are loaded, known as "zero page".
    /// Must be initialized by zeros.
    pub const bootparam = 0x0001_0000;
    /// Where the kernel cmdline is located.
    pub const cmdline = 0x0002_0000;
    /// Where the protected-mode kernel code is loaded
    pub const kernel_base = 0x0010_0000;
    /// Where the initrd is loaded.
    pub const initrd = 0x0600_0000;
};

/// Representation of the linux kernel header.
/// This header compiles with protocol v2.15.
pub const SetupHeader = extern struct {
    /// RO. The number of setup sectors.
    setup_sects: u8 align(1),
    root_flags: u16 align(1),
    syssize: u32 align(1),
    ram_size: u16 align(1),
    vid_mode: u16 align(1),
    root_dev: u16 align(1),
    boot_flag: u16 align(1),
    jump: u16 align(1),
    header: u32 align(1),
    /// RO. Boot protocol version supported.
    version: u16 align(1),
    realmode_swtch: u32 align(1),
    start_sys_seg: u16 align(1),
    kernel_version: u16 align(1),
    /// M. The type of loader. Specify 0xFF if no ID is assigned.
    type_of_loader: u8 align(1),
    /// M. Bitmask.
    loadflags: LoadflagBitfield align(1),
    setup_move_size: u16 align(1),
    code32_start: u32 align(1),
    /// M. The 32-bit linear address of initial ramdisk or ramfs.
    /// Specify 0 if there is no ramdisk or ramfs.
    ramdisk_image: u32 align(1),
    /// M. The size of the initial ramdisk or ramfs.
    ramdisk_size: u32 align(1),
    bootsect_kludge: u32 align(1),
    /// W. Offset of the end of the setup/heap minus 0x200.
    heap_end_ptr: u16 align(1),
    /// W(opt). Extension of the loader ID.
    ext_loader_ver: u8 align(1),
    ext_loader_type: u8 align(1),
    /// W. The 32-bit linear address of the kernel command line.
    cmd_line_ptr: u32 align(1),
    /// R. Highest address that can be used for initrd.
    initrd_addr_max: u32 align(1),
    kernel_alignment: u32 align(1),
    relocatable_kernel: u8 align(1),
    min_alignment: u8 align(1),
    xloadflags: u16 align(1),
    /// R. Maximum size of the cmdline.
    cmdline_size: u32 align(1),
    hardware_subarch: u32 align(1),
    hardware_subarch_data: u64 align(1),
    payload_offset: u32 align(1),
    payload_length: u32 align(1),
    setup_data: u64 align(1),
    pref_address: u64 align(1),
    init_size: u32 align(1),
    handover_offset: u32 align(1),
    kernel_info_offset: u32 align(1),

    /// Bitfield for loadflags.
    const LoadflagBitfield = packed struct(u8) {
        /// If true, the protected-mode code is loaded at 0x100000.
        loaded_high: bool = false,
        /// If true, KASLR enabled.
        kaslr_flag: bool = false,
        /// Unused.
        _unused: u3 = 0,
        /// If false, print early messages.
        quiet_flag: bool = false,
        /// If false, reload the segment registers in the 32bit entry point.
        keep_segments: bool = false,
        /// Set true to indicate that the value entered in the `heap_end_ptr` is valid.
        can_use_heap: bool = false,

        /// Convert to u8.
        pub fn to_u8(self: @This()) u8 {
            return @bitCast(self);
        }
    };

    /// The offset where the header starts in the bzImage.
    pub const header_offset = 0x1F1;

    comptime {
        if (@sizeOf(@This()) != 0x7B) {
            @compileError("Unexpected SetupHeader size");
        }
    }

    /// Instantiate a header from bzImage.
    pub fn from(bytes: []u8) @This() {
        var hdr = std.mem.bytesToValue(
            @This(),
            bytes[header_offset .. header_offset + @sizeOf(@This())],
        );
        if (hdr.setup_sects == 0) {
            hdr.setup_sects = 4;
        }

        return hdr;
    }

    /// Get the offset of the protected-mode kernel code.
    /// Real-mode code consists of the boot sector (1 sector == 512 bytes)
    /// plus the setup code (`setup_sects` sectors).
    pub fn getProtectedCodeOffset(self: @This()) usize {
        return (@as(usize, self.setup_sects) + 1) * 512;
    }
};

pub const E820Entry = extern struct {
    addr: u64 align(1),
    size: u64 align(1),
    type: Type align(1),

    pub const Type = enum(u32) {
        /// RAM.
        ram = 1,
        /// Reserved.
        reserved = 2,
        /// ACPI reclaimable memory.
        acpi = 3,
        /// ACPI NVS memory.
        nvs = 4,
        /// Unusable memory region.
        unusable = 5,
    };

    comptime {
        std.debug.assert(@bitSizeOf(@This()) == 0x14 * 8);
    }
};

/// Port of struct boot_params in linux kernel.
/// Note that fields prefixed with `_` are not implemented and have incorrect types.
pub const BootParams = extern struct {
    /// Maximum number of entries in the E820 map.
    const e820max = 128;

    _screen_info: [0x40]u8 align(1),
    _apm_bios_info: [0x14]u8 align(1),
    _pad2: [4]u8 align(1),
    tboot_addr: u64 align(1),
    ist_info: [0x10]u8 align(1),
    _pad3: [0x10]u8 align(1),
    hd0_info: [0x10]u8 align(1),
    hd1_info: [0x10]u8 align(1),
    _sys_desc_table: [0x10]u8 align(1),
    _olpc_ofw_header: [0x10]u8 align(1),
    _pad4: [0x80]u8 align(1),
    _edid_info: [0x80]u8 align(1),
    _efi_info: [0x20]u8 align(1),
    alt_mem_k: u32 align(1),
    scratch: u32 align(1),
    /// Number of entries in the E820 map.
    e820_entries: u8 align(1),
    eddbuf_entries: u8 align(1),
    edd_mbr_sig_buf_entries: u8 align(1),
    kbd_status: u8 align(1),
    _pad6: [5]u8 align(1),
    /// Setup header.
    hdr: SetupHeader,
    _pad7: [0x290 - SetupHeader.header_offset - @sizeOf(SetupHeader)]u8 align(1),
    _edd_mbr_sig_buffer: [0x10]u32 align(1),
    /// System memory map that can be retrieved by INT 15, E820h.
    e820_map: [e820max]E820Entry align(1),
    _unimplemented: [0x330]u8 align(1),

    comptime {
        if (@sizeOf(@This()) != 0x1000) {
            @compileError("Unexpected BootParams size");
        }
    }

    /// Instantiate a boot params from bzImage.
    pub fn from(bytes: []u8) @This() {
        return std.mem.bytesToValue(
            @This(),
            bytes[0..@sizeOf(@This())],
        );
    }

    /// Add an entry to the E820 map.
    pub fn addE820entry(
        self: *@This(),
        addr: u64,
        size: u64,
        type_: E820Entry.Type,
    ) void {
        self.e820_map[self.e820_entries].addr = addr;
        self.e820_map[self.e820_entries].size = size;
        self.e820_map[self.e820_entries].type = type_;
        self.e820_entries += 1;
    }
};
