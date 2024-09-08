//! Provides kernel page table and memory management functionalities.
//!
//! Before calling `directOffsetMap()`, ymir uses page tables provided by surtr bootloader.
//! That directly maps all available physical memory to virtual memory with offset 0x0.
//! Additionally, surtr maps the ymir loadable image to the virtual address
//! where the ymir ELF requested to load.
//!
//! After calling `directOffsetMap()`,
//! ymir maps all available physical memory to the virtual address with offset `direct_map_base`.
//! These region can be used to access physical memory.
//!
//! After calling `unmapStraightMap()`,
//! ymir unmaps the straight map region starting at address 0x0.
//! It means that ymir no longer uses the memory map provided by UEFI,
//! and has to use the direct map region to access physical memory.

const std = @import("std");
const log = std.log.scoped(.archp);
const Allocator = std.mem.Allocator;

const arch = @import("arch.zig");
const am = @import("asm.zig");

const ymir = @import("ymir");
const mem = ymir.mem;
const BootstrapPageAllocator = mem.BootstrapPageAllocator;
const direct_map_base = ymir.direct_map_base;
const virt2phys = mem.virt2phys;
const phys2virt = mem.phys2virt;
const Virt = mem.Virt;
const Phys = mem.Phys;

pub const PageError = error{
    /// Failed to allocate memory.
    NoMemory,
};

const page_size_4k = mem.page_size_4k;
const page_size_2mb = mem.page_size_2mb;
const page_size_1gb = mem.page_size_1gb;
const page_shift_4k = mem.page_shift_4k;
const page_shift_2mb = mem.page_shift_2mb;
const page_shift_1gb = mem.page_shift_1gb;
const page_mask_4k = mem.page_mask_4k;
const page_mask_2mb = mem.page_mask_2mb;
const page_mask_1gb = mem.page_mask_1gb;

/// Shift in bits to extract the level-4 index from a virtual address.
const lv4_shift = 39;
/// Shift in bits to extract the level-3 index from a virtual address.
const lv3_shift = 30;
/// Shift in bits to extract the level-2 index from a virtual address.
const lv2_shift = 21;
/// Shift in bits to extract the level-1 index from a virtual address.
const lv1_shift = 12;
/// Mask to extract page entry index from a shifted virtual address.
const index_mask = 0x1FF;

/// Number of entries in a page table.
const num_table_entries: usize = 512;

/// Length of the implemented bits.
const implemented_bit_length = 48;
/// Most significant implemented bit in 0-origin.
const msi_bit = 47;

/// Offset from physical to virtual address for page tables.
/// This value is determined by surtr bootloader and a backing UEFI firmware.
/// For now, we only assume OVMF as UEFI,
/// that directly maps available physical memory to virtual memory using 2MiB pages.
/// Therefore, the offset is 0x0 for OVMF.
const phys_virt_offset = 0x0;

/// Return true if the given address is canonical form.
/// The address is in canonical form if address bits 63 through 48 are copies of bit 47.
pub fn isCanonical(addr: Virt) bool {
    if ((addr >> msi_bit) & 1 == 0) {
        return (addr >> (implemented_bit_length)) == 0;
    } else {
        return addr >> (implemented_bit_length) == 0xFFFF;
    }
}

/// Get the level-4 page table of the current process.
pub fn getLv4PageTable() []Lv4PageTableEntry {
    const cr3 = am.readCr3() + phys_virt_offset;
    const lv4_table_ptr: [*]Lv4PageTableEntry = @ptrFromInt(cr3 & ~@as(u64, page_mask_4k));
    return lv4_table_ptr[0..num_table_entries];
}

/// Get the level-3 page table at the given address.
pub fn getLv3PageTable(lv3_table_addr: Phys) []Lv3PageTableEntry {
    const lv3_table_ptr: [*]Lv3PageTableEntry = @ptrFromInt(lv3_table_addr + phys_virt_offset);
    return lv3_table_ptr[0..num_table_entries];
}

/// Get the level-2 page table at the given address.
pub fn getLv2PageTable(lv2_table_addr: Phys) []Lv2PageTableEntry {
    const lv2_table_ptr: [*]Lv2PageTableEntry = @ptrFromInt(lv2_table_addr + phys_virt_offset);
    return lv2_table_ptr[0..num_table_entries];
}

/// Get the level-1 page table at the given address.
pub fn getLv1PageTable(lv1_table_addr: Phys) []Lv1PageTableEntry {
    const lv1_table_ptr: [*]Lv1PageTableEntry = @ptrFromInt(lv1_table_addr + phys_virt_offset);
    return lv1_table_ptr[0..num_table_entries];
}

/// Translate the given virtual address to physical address by walking page tables.
/// If the translation fails, return null.
pub fn translateWalk(addr: Virt) ?Phys {
    if (!isCanonical(addr)) return null;

    const lv4_table = getLv4PageTable();
    const lv4_index = (addr >> lv4_shift) & index_mask;
    const lv4_entry = &lv4_table[lv4_index];
    if (!lv4_entry.present) return null;

    const lv3_table = getLv3PageTable(lv4_entry.address());
    const lv3_index = (addr >> lv3_shift) & index_mask;
    const lv3_entry = &lv3_table[lv3_index];
    if (!lv3_entry.present) return null;
    if (lv3_entry.ps) { // 1GiB page
        return lv3_entry.address() + (addr & page_mask_1gb);
    }

    const lv2_table = getLv2PageTable(lv3_entry.address());
    const lv2_index = (addr >> lv2_shift) & index_mask;
    const lv2_entry = &lv2_table[lv2_index];
    if (!lv2_entry.present) return null;
    if (lv2_entry.ps) { // 2MiB page
        return lv2_entry.address() + (addr & page_mask_4k);
    }

    const lv1_table = getLv1PageTable(lv2_entry.address());
    const lv1_index = (addr >> lv1_shift) & index_mask;
    const lv1_entry = &lv1_table[lv1_index];
    if (!lv1_entry.present) return null;
    return lv1_entry.phys + (addr & page_mask_4k);
}

/// Translate the given guest virtual address to guest physical address.
pub fn guestTranslateWalk(gva: Virt, cr3: Phys, guest_base: Phys) ?Phys {
    const lv4tbl: [*]Lv4PageTableEntry = @ptrFromInt(phys2virt((cr3 & ~page_mask_4k) + guest_base));
    const lv4index = (gva >> lv4_shift) & index_mask;
    const lv4ent = &lv4tbl[lv4index];

    const lv3tbl: [*]Lv3PageTableEntry = @ptrFromInt(phys2virt(lv4ent.address() + guest_base));
    const lv3index = (gva >> lv3_shift) & index_mask;
    const lv3ent = &lv3tbl[lv3index];
    if (!lv3ent.present) return null;
    if (lv3ent.ps) return lv3ent.address() + (gva & page_mask_1gb);

    const lv2tbl: [*]Lv2PageTableEntry = @ptrFromInt(phys2virt(lv3ent.address() + guest_base));
    const lv2index = (gva >> lv2_shift) & index_mask;
    const lv2ent = &lv2tbl[lv2index];
    if (!lv2ent.present) return null;
    if (lv2ent.ps) return lv2ent.address() + (gva & page_mask_2mb);

    const lv1tbl: [*]Lv1PageTableEntry = @ptrFromInt(phys2virt(lv2ent.address() + guest_base));
    const lv1index = (gva >> lv1_shift) & index_mask;
    const lv1ent = &lv1tbl[lv1index];
    if (!lv1ent.present) return null;
    return lv1ent.address() + (gva & page_mask_4k);
}

/// Clone page tables prepared by UEFI.
/// After calling this function, cloned page tables are set to CR3.
pub fn cloneUefiPageTables() !void {
    const lv4_table = getLv4PageTable();
    const new_lv4_ptr: [*]Lv4PageTableEntry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv4_table = new_lv4_ptr[0..num_table_entries];
    @memcpy(new_lv4_table, lv4_table);

    for (new_lv4_table) |*lv4_entry| {
        if (lv4_entry.present) {
            const lv3_table = getLv3PageTable(lv4_entry.address());
            const new_lv3_table = try cloneLevel3Table(lv3_table);
            lv4_entry.phys = @truncate(@as(u64, @intFromPtr(new_lv3_table.ptr)) >> page_shift_4k);
        }
    }

    am.loadCr3(@intFromPtr(new_lv4_table));
}

fn cloneLevel3Table(lv3_table: []Lv3PageTableEntry) ![]Lv3PageTableEntry {
    const new_lv3_ptr: [*]Lv3PageTableEntry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv3_table = new_lv3_ptr[0..num_table_entries];
    @memcpy(new_lv3_table, lv3_table);

    for (new_lv3_table) |*lv3_entry| {
        if (!lv3_entry.present) continue;
        if (lv3_entry.ps) continue;

        const lv2_table = getLv2PageTable(lv3_entry.address());
        const new_lv2_table = try cloneLevel2Table(lv2_table);
        lv3_entry.phys = @truncate(@as(u64, @intFromPtr(new_lv2_table.ptr)) >> page_shift_4k);
    }

    return new_lv3_table;
}

fn cloneLevel2Table(lv2_table: []Lv2PageTableEntry) ![]Lv2PageTableEntry {
    const new_lv2_ptr: [*]Lv2PageTableEntry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv2_table = new_lv2_ptr[0..num_table_entries];
    @memcpy(new_lv2_table, lv2_table);

    for (new_lv2_table) |*lv2_entry| {
        if (!lv2_entry.present) continue;
        if (lv2_entry.ps) continue;

        const lv1_table = getLv1PageTable(lv2_entry.address());
        const new_lv1_table = try cloneLevel1Table(lv1_table);
        lv2_entry.phys = @truncate(@as(u64, @intFromPtr(new_lv1_table.ptr)) >> page_shift_4k);
    }

    return new_lv2_table;
}

fn cloneLevel1Table(lv1_table: []Lv1PageTableEntry) ![]Lv1PageTableEntry {
    const new_lv1_ptr: [*]Lv1PageTableEntry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv1_table = new_lv1_ptr[0..num_table_entries];
    @memcpy(new_lv1_table, lv1_table);

    return new_lv1_table;
}

/// Directly map all memory with offset
/// After calling this function, it is safe to unmap direct mappings.
pub fn directOffsetMap() !void {
    const lv4_table = getLv4PageTable();
    const directmap_lv4_index = (direct_map_base >> lv4_shift) & index_mask;

    for (lv4_table[0..directmap_lv4_index], 0..) |*lv4_entry, i| {
        if (!lv4_entry.present) continue;

        const lv3_table = getLv3PageTable(lv4_entry.address());
        lv4_table[directmap_lv4_index + i] = Lv4PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .phys = @truncate(@as(u64, @intFromPtr(lv3_table.ptr)) >> page_shift_4k),
        };
    }

    reloadCr3();
}

/// Unmap straight map region starting at address 0x0.
/// Note that after calling this function,
/// BootstrapPageAllocator returns invalid virtual address because they are unmapped by this function.
pub fn unmapStraightMap() !void {
    const lv4_table = getLv4PageTable();
    const directmap_lv4_index = (direct_map_base >> lv4_shift) & index_mask;

    for (lv4_table[0..directmap_lv4_index]) |*lv4_entry| {
        if (!lv4_entry.present) continue;
        lv4_entry.present = false;
    }

    reloadCr3();
}

fn reloadCr3() void {
    const lv4_table = getLv4PageTable();
    am.loadCr3(@intFromPtr(lv4_table.ptr));
}

/// Show the process of the address translation for the given linear address.
pub fn showPageTable(lin_addr: Virt, logger: anytype) void {
    const pml4_index = (lin_addr >> lv4_shift) & index_mask;
    const pdp_index = (lin_addr >> lv3_shift) & index_mask;
    const pdt_index = (lin_addr >> lv2_shift) & index_mask;
    const pt_index = (lin_addr >> lv1_shift) & index_mask;
    logger.err(
        "Linear Address: 0x{X:0>16} (0x{X}, 0x{X}, 0x{X}, 0x{X})",
        .{ lin_addr, pml4_index, pdp_index, pdt_index, pt_index },
    );

    const cr3 = am.readCr3();
    const lv4_table: [*]Lv4PageTableEntry = @ptrFromInt(phys2virt(cr3));
    const lv4_entry = lv4_table[pml4_index];
    const lv3_table: [*]Lv3PageTableEntry = @ptrFromInt(phys2virt(lv4_entry.phys << page_shift_4k));
    const lv3_entry = lv3_table[pdp_index];
    const lv2_table: [*]Lv2PageTableEntry = @ptrFromInt(phys2virt(lv3_entry.phys << page_shift_4k));
    const lv2_entry = lv2_table[pdt_index];

    logger.info("Lv4: 0x{X:0>16}", .{@intFromPtr(lv4_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pml4_index, std.mem.bytesAsValue(u64, &lv4_entry).* });
    logger.info("Lv3: 0x{X:0>16}", .{@intFromPtr(lv3_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pdp_index, std.mem.bytesAsValue(u64, &lv3_entry).* });
    logger.info("Lv2: 0x{X:0>16}", .{@intFromPtr(lv2_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pdt_index, std.mem.bytesAsValue(u64, &lv2_entry).* });

    if (!lv2_entry.ps) {
        const lv1_table: [*]Lv1PageTableEntry = @ptrFromInt(phys2virt(lv2_entry.phys << page_shift_4k));
        const lv1_entry = lv1_table[pt_index];
        logger.info("Lv1: 0x{X:0>16}", .{@intFromPtr(lv1_table)});
        logger.info("\t[{d}]: 0x{X:0>16}", .{ pt_index, std.mem.bytesAsValue(u64, &lv1_entry).* });
    }
}

/// Level-4 (First) page table entry, PML4E.
/// This entry can map 512GiB region or reference a level-3 page table.
const Lv4PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 512GB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 512GB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the PDP Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the PDP Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Ignored.
    _ignored1: u1 = 0,
    /// ReservedZ.
    _reserved1: u1 = 0,
    /// Ignored
    _ignored2: u3 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// 4KB aligned address of the PDP Table.
    phys: u52,

    /// Get a new PML4E entry with the present bit set to false.
    pub fn new_nopresent() Lv4PageTableEntry {
        return Lv4PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .phys = 0,
        };
    }

    /// Get a new PML4E entry.
    pub fn new(phys_pdpt: *Lv3PageTableEntry) Lv4PageTableEntry {
        return Lv4PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .phys = @truncate(@as(u64, @intFromPtr(phys_pdpt)) >> page_shift_4k),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv4PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

/// Level-3 page table entry, PDPTE.
/// This entry can map 1GiB page or reference a level-2 page table.
const Lv3PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 1GiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the GiB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the PD Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the PD Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Ignored.
    _ignored1: u1 = 0,
    /// Page Size.
    /// If set to true, the entry maps a 1GiB page.
    /// If set to false, the entry references a PD Table.
    ps: bool,
    /// Ignored
    _ignored2: u3 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// 4KB aligned address of the PD Table.
    phys: u52,

    /// Get a new PDPT entry with the present bit set to false.
    pub fn new_nopresent() Lv3PageTableEntry {
        return Lv3PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys = 0,
        };
    }

    /// Get a new PDPT entry.
    pub fn new(phys_pdt: u64) Lv3PageTableEntry {
        return Lv3PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = false,
            .phys = @truncate(phys_pdt >> page_shift_4k),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv3PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

/// Level-2 page table entry, PDE.
/// This entry can map a 2MiB page or reference a level-1 page table.
const Lv2PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 2MiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 2Mib region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the 2MiB page or Page Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the 2MiB page or Page Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Dirty bit.
    /// Indicates wheter software has written to the 2MiB page.
    /// Ignored when this entry references a Page Table.
    dirty: bool = false,
    /// Page Size.
    /// If set to true, the entry maps a 2Mib page.
    /// If set to false, the entry references a Page Table.
    ps: bool,
    /// Ignored when CR4.PGE != 1.
    /// Ignored when this entry references a 2MiB page.
    global: bool = false,
    /// Ignored
    _ignored2: u2 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// When the entry maps a 2MiB page, physical address of the 2MiB page.
    /// When the entry references a Page Table, 4KB aligned address of the Page Table.
    phys: u52,

    /// Get a new PDT entry with the present bit set to false.
    pub fn new_nopresent() Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = false,
            .rw = false,
            .us = false,
            .ps = false,
            .phys = 0,
        };
    }

    /// Get a new PDT entry that maps a 2MiB page.
    pub fn new_4mb(phys: u64) Lv2PageTableEntry {
        return Lv2PageTableEntry{
            .present = true,
            .rw = true,
            .us = false,
            .ps = true,
            .phys = @truncate(phys >> page_shift_4k),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv2PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

/// Level-1 page table entry, PTE.
/// This entry can map 4KiB page.
const Lv1PageTableEntry = packed struct(u64) {
    /// Present.
    present: bool = true,
    /// Read/Write.
    /// If set to false, wirte access is not allowed to the 4KiB region.
    rw: bool,
    /// User/Supervisor.
    /// If set to false, user-mode access is not allowed to the 4KiB region.
    us: bool,
    /// Page-level writh-through.
    /// Indirectly determines the memory type used to access the 4KiB page or Page Table.
    pwt: bool = false,
    /// Page-level cache disable.
    /// Indirectly determines the memory type used to access the 4KiB page or Page Table.
    pcd: bool = false,
    /// Accessed.
    /// Indicates wheter this entry has been used for translation.
    accessed: bool = false,
    /// Dirty bit.
    /// Indicates wheter software has written to the 4KiB page.
    /// Ignored when this entry references a Page Table.
    dirty: bool = false,
    /// Indirectly determines the memory type used to access the 4KiB page.
    pat: bool,
    /// Global. Whether the translation is global.
    /// Ignored when CR4.PGE != 1.
    global: bool = false,
    /// Ignored
    _ignored2: u2 = 0,
    /// Ignored except for HLAT paging.
    restart: bool = false,
    /// Physical address of the 4KiB page.
    phys: u52,

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv1PageTableEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

// ========================================

const testing = std.testing;

test {
    testing.refAllDeclsRecursive(@This());
}

test "isCanonical" {
    try testing.expectEqual(true, isCanonical(0x0));
    try testing.expectEqual(true, isCanonical(0x0000_7FFF_FFFF_FFFF));
    try testing.expectEqual(false, isCanonical(0x0000_8000_0000_0000));
    try testing.expectEqual(false, isCanonical(0x1000_0000_0000_0000));
    try testing.expectEqual(false, isCanonical(0xFFFF_7FFF_FFFF_FFFF));
    try testing.expectEqual(true, isCanonical(0xFFFF_FFFF_8000_0000));
    try testing.expectEqual(true, isCanonical(0xFFFF_8880_0000_0000));
}
