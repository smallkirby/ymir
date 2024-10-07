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
const direct_map_size = ymir.direct_map_size;
const virt2phys = mem.virt2phys;
const phys2virt = mem.phys2virt;
const Virt = mem.Virt;
const Phys = mem.Phys;

pub const PageError = error{
    /// Failed to allocate memory.
    OutOfMemory,
    /// Invalid address.
    InvalidAddress,
    /// Specified address is not mapped.
    NotMapped,
};

const page_size_4k = mem.page_size_4k;
const page_size_2mb = mem.page_size_2mb;
const page_size_1gb = mem.page_size_1gb;
const page_size_512gb = page_size_1gb * 512;
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

/// Page type based on its size.
pub const PageSize = enum {
    /// 4KiB
    k4,
    /// 2MiB
    m2,
    /// 1GiB
    g1,
};

/// Page attributes.
pub const PageAttribute = enum {
    /// RO
    read_only,
    /// RW
    read_write,
    /// RX
    executable,
};

/// Return true if the given address is canonical form.
/// The address is in canonical form if address bits 63 through 48 are copies of bit 47.
pub fn isCanonical(addr: Virt) bool {
    if ((addr >> msi_bit) & 1 == 0) {
        return (addr >> (implemented_bit_length)) == 0;
    } else {
        return addr >> (implemented_bit_length) == 0xFFFF;
    }
}

fn getTable(T: type, addr: Phys, offset: usize) []T {
    const ptr: [*]T = @ptrFromInt((phys2virt(addr) & ~page_mask_4k) + offset);
    return ptr[0..num_table_entries];
}

/// Get the level-4 page table of the current process.
fn getLv4Table(cr3: Phys) []Lv4Entry {
    return getTable(Lv4Entry, cr3, 0);
}

/// Get the level-3 page table at the given address.
fn getLv3Table(lv3_table_addr: Phys) []Lv3Entry {
    return getTable(Lv3Entry, lv3_table_addr, 0);
}

/// Get the level-2 page table at the given address.
fn getLv2Table(lv2_table_addr: Phys) []Lv2Entry {
    return getTable(Lv2Entry, lv2_table_addr, 0);
}

/// Get the level-1 page table at the given address.
fn getLv1Table(lv1_table_addr: Phys) []Lv1Entry {
    return getTable(Lv1Entry, lv1_table_addr, 0);
}

fn getEntry(T: type, vaddr: Virt, paddr: Phys, offset: usize) *T {
    const table = getTable(T, paddr, offset);
    const shift = switch (T) {
        Lv4Entry => lv4_shift,
        Lv3Entry => lv3_shift,
        Lv2Entry => lv2_shift,
        Lv1Entry => lv1_shift,
        else => @compileError("Unsupported type"),
    };
    return &table[(vaddr >> shift) & index_mask];
}

/// Get the level-4 page table entry for the given virtual address.
fn getLv4Entry(addr: Virt, cr3: Phys) *Lv4Entry {
    return getEntry(Lv4Entry, addr, cr3, 0);
}

/// Get the level-3 page table entry for the given virtual address.
/// Requires that the level-4 page table is present.
fn getLv3Entry(addr: Virt, lv3_table_addr: Phys) *Lv3Entry {
    return getEntry(Lv3Entry, addr, lv3_table_addr, 0);
}

/// Get the level-2 page table entry for the given virtual address.
/// Requires that the level-3 page table is present and it reference a level-2 page table.
fn getLv2Entry(addr: Virt, lv2_table_addr: Phys) *Lv2Entry {
    return getEntry(Lv2Entry, addr, lv2_table_addr, 0);
}

/// Get the level-1 page table entry for the given virtual address.
/// Requires that the level-2 page table is present and it reference a level-1 page table.
fn getLv1Entry(addr: Virt, lv1_table_addr: Phys) *Lv1Entry {
    return getEntry(Lv1Entry, addr, lv1_table_addr, 0);
}

/// Get the level-4 page table of the current guest process.
fn getLv4GuestTable(cr3: Phys, guest_base: u64) []Lv4Entry {
    return getTable(Lv4Entry, cr3, guest_base);
}

/// Get the level-3 page table at the given address of the guest.
fn getLv3GuestTable(lv3_table_addr: Phys, guest_base: u64) []Lv3Entry {
    return getTable(Lv3Entry, lv3_table_addr, guest_base);
}

/// Get the level-2 page table at the given address of the guest.
fn getLv2GuestTable(lv2_table_addr: Phys, guest_base: u64) []Lv2Entry {
    return getTable(Lv2Entry, lv2_table_addr, guest_base);
}

/// Get the level-1 page table at the given address of the guest.
fn getLv1GuestTable(lv1_table_addr: Phys, guest_base: u64) []Lv1Entry {
    return getTable(Lv1Entry, lv1_table_addr, guest_base);
}

/// Get the level-4 page table entry of the current guest process for the given guest virtual address.
fn getLv4GuestEntry(gva: Virt, cr3: Phys, guest_base: u64) *Lv4Entry {
    return getEntry(Lv4Entry, gva, cr3, guest_base);
}

/// Get the level-3 page table entry of the current guest process for the given guest virtual address.
/// Requires that the level-4 page table is present.
fn getLv3GuestEntry(gva: Virt, lv3_table_addr: Phys, guest_base: u64) *Lv3Entry {
    return getEntry(Lv3Entry, gva, lv3_table_addr, guest_base);
}

/// Get the level-2 page table entry of the current guest process for the given guest virtual address.
/// Requires that the level-3 page table is present and it reference a level-2 page table.
fn getLv2GuestEntry(gva: Virt, lv2_table_addr: Phys, guest_base: u64) *Lv2Entry {
    return getEntry(Lv2Entry, gva, lv2_table_addr, guest_base);
}

/// Get the level-1 page table entry of the current guest process for the given guest virtual address.
/// Requires that the level-2 page table is present and it reference a level-1 page table.
fn getLv1GuestEntry(gva: Virt, lv1_table_addr: Phys, guest_base: u64) *Lv1Entry {
    return getEntry(Lv1Entry, gva, lv1_table_addr, guest_base);
}

/// Translate the given virtual address to physical address by walking page tables.
/// If the translation fails, return null.
pub fn translateWalk(addr: Virt) ?Phys {
    if (!isCanonical(addr)) return null;

    const lv4_entry = getLv4Entry(addr, am.readCr3());
    if (!lv4_entry.present) return null;

    const lv3_entry = getLv3Entry(addr, lv4_entry.address());
    if (!lv3_entry.present) return null;
    if (lv3_entry.ps) { // 1GiB page
        return lv3_entry.address() + (addr & page_mask_1gb);
    }

    const lv2_entry = getLv2Entry(addr, lv3_entry.address());
    if (!lv2_entry.present) return null;
    if (lv2_entry.ps) { // 2MiB page
        return lv2_entry.address() + (addr & page_mask_4k);
    }

    const lv1_entry = getLv1Entry(addr, lv2_entry.address());
    if (!lv1_entry.present) return null;
    return lv1_entry.phys + (addr & page_mask_4k);
}

/// Translate the given guest virtual address to guest physical address.
pub fn guestTranslateWalk(gva: Virt, cr3: Phys, guest_base: Phys) ?Phys {
    const lv4ent = getLv4GuestEntry(gva, cr3, guest_base);

    const lv3ent = getLv3GuestEntry(gva, lv4ent.address(), guest_base);
    if (!lv3ent.present) return null;
    if (lv3ent.ps) return lv3ent.address() + (gva & page_mask_1gb);

    const lv2ent = getLv2GuestEntry(gva, lv3ent.address(), guest_base);
    if (!lv2ent.present) return null;
    if (lv2ent.ps) return lv2ent.address() + (gva & page_mask_2mb);

    const lv1ent = getLv1GuestEntry(gva, lv2ent.address(), guest_base);
    if (!lv1ent.present) return null;
    return lv1ent.address() + (gva & page_mask_4k);
}

/// Recursively clone page tables provided by UEFI.
/// After calling this function, cloned page tables are set to CR3.
/// Paged used for the old page tables can be safely freed / reused.
pub fn cloneUefiPageTables() PageError!void {
    // Lv4 table provided by UEFI.
    const lv4_table = getLv4Table(am.readCr3());

    // New Lv4 table. Assuming the initial direct mapping is still valid and VA is equal to PA.
    if (phys2virt(0) != 0) @panic("Invalid page mapping phase for cloning UEFI page tables");
    const new_lv4_ptr: [*]Lv4Entry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv4_table = new_lv4_ptr[0..num_table_entries];
    @memcpy(new_lv4_table, lv4_table);

    // Recursively clone tables.
    for (new_lv4_table) |*lv4_entry| {
        if (lv4_entry.present) {
            const lv3_table = getLv3Table(lv4_entry.address());
            const new_lv3_table = try cloneLevel3Table(lv3_table);
            lv4_entry.phys = @truncate(virt2phys(new_lv3_table.ptr) >> page_shift_4k);
        }
    }

    am.loadCr3(@intFromPtr(new_lv4_table));
}

fn cloneLevel3Table(lv3_table: []Lv3Entry) PageError![]Lv3Entry {
    const new_lv3_ptr: [*]Lv3Entry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv3_table = new_lv3_ptr[0..num_table_entries];
    @memcpy(new_lv3_table, lv3_table);

    for (new_lv3_table) |*lv3_entry| {
        if (!lv3_entry.present) continue;
        if (lv3_entry.ps) continue;

        const lv2_table = getLv2Table(lv3_entry.address());
        const new_lv2_table = try cloneLevel2Table(lv2_table);
        lv3_entry.phys = @truncate(virt2phys(new_lv2_table.ptr) >> page_shift_4k);
    }

    return new_lv3_table;
}

fn cloneLevel2Table(lv2_table: []Lv2Entry) PageError![]Lv2Entry {
    const new_lv2_ptr: [*]Lv2Entry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv2_table = new_lv2_ptr[0..num_table_entries];
    @memcpy(new_lv2_table, lv2_table);

    for (new_lv2_table) |*lv2_entry| {
        if (!lv2_entry.present) continue;
        if (lv2_entry.ps) continue;

        const lv1_table = getLv1Table(lv2_entry.address());
        const new_lv1_table = try cloneLevel1Table(lv1_table);
        lv2_entry.phys = @truncate(virt2phys(new_lv1_table.ptr) >> page_shift_4k);
    }

    return new_lv2_table;
}

fn cloneLevel1Table(lv1_table: []Lv1Entry) PageError![]Lv1Entry {
    const new_lv1_ptr: [*]Lv1Entry = @ptrCast(try BootstrapPageAllocator.allocatePage());
    const new_lv1_table = new_lv1_ptr[0..num_table_entries];
    @memcpy(new_lv1_table, lv1_table);

    return new_lv1_table;
}

/// Directly map all memory with offset.
/// After calling this function, it is safe to unmap direct mappings.
pub fn directOffsetMap() PageError!void {
    comptime {
        if (direct_map_size % page_size_512gb != 0) {
            @compileError("direct_map_size must be multiple of 512GB");
        }
        if (direct_map_base % page_size_512gb != 0) {
            @compileError("direct_map_base must be multiple of 512GB");
        }
    }

    const lv4tbl = getLv4Table(am.readCr3());
    const lv4idx_start = (direct_map_base >> lv4_shift) & index_mask;
    const lv4idx_end = lv4idx_start + (direct_map_size >> lv4_shift);

    // Create the direct mapping using 1GiB pages.
    for (lv4idx_start..lv4idx_end, 0..) |lv4idx, i| {
        if (lv4tbl[lv4idx].present)
            @panic("UEFI mapping overlaps with direct mapping");
        const lv3tbl: [*]Lv3Entry = @ptrCast(try BootstrapPageAllocator.allocatePage());
        for (0..num_table_entries) |lv3idx| {
            lv3tbl[lv3idx] = Lv3Entry.newMapPage(
                (i << lv4_shift) + (lv3idx << lv3_shift),
                true,
            );
        }
        lv4tbl[lv4idx] = Lv4Entry.newMapTable(lv3tbl, true);
    }

    // TODO: this function does not modify CR3. Need to invalidate TLB in other way?
    reloadCr3();
}

/// Unmap straight map region starting at address 0x0.
/// Note that after calling this function,
/// BootstrapPageAllocator returns invalid virtual address because they are unmapped by this function.
pub fn unmapStraightMap() PageError!void {
    const lv4_table = getLv4Table(am.readCr3());
    const lv4idx_end = (direct_map_base >> lv4_shift) & index_mask;

    for (lv4_table[0..lv4idx_end]) |*lv4_entry| {
        if (!lv4_entry.present) continue;
        lv4_entry.present = false;
    }

    // TODO: this function does not modify CR3. Need to invalidate TLB in other way?
    reloadCr3();
}

fn reloadCr3() void {
    const lv4_table = getLv4Table(am.readCr3());
    am.loadCr3(virt2phys(lv4_table.ptr));
}

/// Change the page attribute.
pub fn changePageAttribute(size: PageSize, virt: Virt, attr: PageAttribute, allocator: Allocator) PageError!void {
    if (!isCanonical(virt)) return error.InvalidAddress;

    const rw = switch (attr) {
        .read_only, .executable => false,
        .read_write => true,
    };
    const xd = attr == .executable;

    const lv4ent = getLv4Entry(virt, am.readCr3());
    if (!lv4ent.present) return error.NotMapped;

    const lv3ent = getLv3Entry(virt, lv4ent.address());
    if (!lv3ent.present) return error.NotMapped;
    if (size == .g1) {
        lv3ent.rw = rw;
        lv3ent.xd = xd;
        return reloadCr3();
    }
    if (lv3ent.ps) try splitTable(Lv3Entry, lv3ent, allocator);

    const lv2ent = getLv2Entry(virt, lv3ent.address());
    if (!lv2ent.present) return error.NotMapped;
    if (size == .m2) {
        lv2ent.rw = rw;
        lv2ent.xd = xd;
        return reloadCr3();
    }
    if (lv2ent.ps) try splitTable(Lv2Entry, lv2ent, allocator);

    const lv1ent = getLv1Entry(virt, lv2ent.address());
    if (!lv1ent.present) return error.NotMapped;
    lv1ent.rw = false;
    lv1ent.xd = false;
    return reloadCr3();
}

/// Split the 1GiB page into 2MiB pages.
fn splitTable(T: type, ent: *T, allocator: Allocator) PageError!void {
    const page = ent.address();
    const U = switch (T) {
        Lv3Entry => Lv2Entry,
        Lv2Entry => Lv1Entry,
        else => @compileError("Unsupported type"),
    };
    const page_size = switch (U) {
        Lv2Entry => page_size_2mb,
        Lv1Entry => page_size_4k,
        else => @compileError("Unsupported type"),
    };
    const tbl = try allocator.alloc(U, num_table_entries);
    for (0..num_table_entries) |i| {
        tbl[i] = U.newMapPage(page + i * page_size, true);
    }
    ent.* = T.newMapTable(tbl.ptr, true);
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
    const lv4_table: [*]Lv4Entry = @ptrFromInt(phys2virt(cr3));
    const lv4_entry = lv4_table[pml4_index];
    const lv3_table: [*]Lv3Entry = @ptrFromInt(phys2virt(lv4_entry.phys << page_shift_4k));
    const lv3_entry = lv3_table[pdp_index];
    const lv2_table: [*]Lv2Entry = @ptrFromInt(phys2virt(lv3_entry.phys << page_shift_4k));
    const lv2_entry = lv2_table[pdt_index];

    logger.info("Lv4: 0x{X:0>16}", .{@intFromPtr(lv4_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pml4_index, std.mem.bytesAsValue(u64, &lv4_entry).* });
    logger.info("Lv3: 0x{X:0>16}", .{@intFromPtr(lv3_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pdp_index, std.mem.bytesAsValue(u64, &lv3_entry).* });
    logger.info("Lv2: 0x{X:0>16}", .{@intFromPtr(lv2_table)});
    logger.info("\t[{d}]: 0x{X:0>16}", .{ pdt_index, std.mem.bytesAsValue(u64, &lv2_entry).* });

    if (!lv2_entry.ps) {
        const lv1_table: [*]Lv1Entry = @ptrFromInt(phys2virt(lv2_entry.phys << page_shift_4k));
        const lv1_entry = lv1_table[pt_index];
        logger.info("Lv1: 0x{X:0>16}", .{@intFromPtr(lv1_table)});
        logger.info("\t[{d}]: 0x{X:0>16}", .{ pt_index, std.mem.bytesAsValue(u64, &lv1_entry).* });
    }
}

const TableLevel = enum {
    lv4,
    lv3,
    lv2,
    lv1,
};

fn EntryBase(table_level: TableLevel) type {
    return packed struct(u64) {
        const Self = @This();
        const level = table_level;
        const LowerType = switch (level) {
            .lv4 => Lv3Entry,
            .lv3 => Lv2Entry,
            .lv2 => Lv1Entry,
            .lv1 => struct {},
        };

        /// Present.
        present: bool = true,
        /// Read/Write.
        /// If set to false, wirte access is not allowed to the region.
        rw: bool,
        /// User/Supervisor.
        /// If set to false, user-mode access is not allowed to the region.
        us: bool,
        /// Page-level writh-through.
        /// Indirectly determines the memory type used to access the page or page table.
        pwt: bool = false,
        /// Page-level cache disable.
        /// Indirectly determines the memory type used to access the page or page table.
        pcd: bool = false,
        /// Accessed.
        /// Indicates wheter this entry has been used for translation.
        accessed: bool = false,
        /// Dirty bit.
        /// Indicates wheter software has written to the 2MiB page.
        /// Ignored when this entry references a page table.
        dirty: bool = false,
        /// Page Size.
        /// If set to true, the entry maps a page.
        /// If set to false, the entry references a page table.
        ps: bool,
        /// Ignored when CR4.PGE != 1.
        /// Ignored when this entry references a page table.
        /// Ignored for level-4 entries.
        global: bool = true,
        /// Ignored
        _ignored1: u2 = 0,
        /// Ignored except for HLAT paging.
        restart: bool = false,
        /// When the entry maps a page, physical address of the page.
        /// When the entry references a page table, 4KB aligned address of the page table.
        phys: u51,
        /// Execute Disable.
        xd: bool = false,

        /// Get the physical address of the page or page table that this entry references or maps.
        pub inline fn address(self: Self) Phys {
            return @as(u64, @intCast(self.phys)) << page_shift_4k;
        }

        /// Get a new page table entry that references a page table.
        pub fn newMapTable(table: [*]LowerType, present: bool) Self {
            if (level == .lv1) @compileError("Lv1 entry cannot reference a page table");
            return Self{
                .present = present,
                .rw = true,
                .us = false,
                .ps = false,
                .phys = @truncate(virt2phys(table) >> page_shift_4k),
            };
        }

        /// Get a new page table entry that maps a page.
        pub fn newMapPage(phys: Phys, present: bool) Self {
            if (level == .lv4) @compileError("Lv4 entry cannot map a page");
            return Self{
                .present = present,
                .rw = true,
                .us = false,
                .ps = true,
                .phys = @truncate(phys >> page_shift_4k),
            };
        }
    };
}

const Lv4Entry = EntryBase(.lv4);
const Lv3Entry = EntryBase(.lv3);
const Lv2Entry = EntryBase(.lv2);
const Lv1Entry = EntryBase(.lv1);

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
