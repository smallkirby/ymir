const std = @import("std");
const log = std.log.scoped(.archp);
const uefi = std.os.uefi;
const elf = std.elf;
const BootServices = uefi.tables.BootServices;

const am = @import("asm.zig");

pub const PageError = error{
    /// Failed to allocate memory.
    NoMemory,
    /// Requested page table entry is not present.
    NotPresent,
    /// Given virtual address is not canonical.
    NotCanonical,
    /// Given address is invalid.
    InvalidAddress,
    /// Requested mapping already exists.
    AlreadyMapped,
};

pub const kib = 1024;
pub const mib = 1024 * kib;
pub const gib = 1024 * mib;

/// Size in bytes of a 4K page.
pub const page_size_4k = 4 * kib;
/// Size in bytes of a 2M page.
pub const page_size_2mb = page_size_4k << 9;
/// Size in bytes of a 1G page.
pub const page_size_1gb = page_size_2mb << 9;
/// Shift in bits for a 4K page.
pub const page_shift_4k = 12;
/// Shift in bits for a 2M page.
pub const page_shift_2mb = 21;
/// Shift in bits for a 1G page.
pub const page_shift_1gb = 30;
/// Mask for a 4K page.
pub const page_mask_4k: u64 = page_size_4k - 1;
/// Mask for a 2M page.
pub const page_mask_2mb: u64 = page_size_2mb - 1;
/// Mask for a 1G page.
pub const page_mask_1gb: u64 = page_size_1gb - 1;
/// Number of entries in a page table.
const num_table_entries: usize = 512;

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

/// Length of the implemented bits.
const implemented_bit_length = 48;
/// Most significant implemented bit in 0-origin.
const msi_bit = 47;

/// Physical address.
pub const Phys = u64;
/// Virtual address.
pub const Virt = u64;

pub const PageAttribute = enum {
    /// RO
    read_only,
    /// RW
    read_write,
    /// RX
    executable,

    pub fn fromFlags(flags: u32) PageAttribute {
        return if (flags & elf.PF_X != 0) .executable else if (flags & elf.PF_W != 0) .read_write else .read_only;
    }
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

fn getTable(T: type, addr: Phys) []T {
    const ptr: [*]T = @ptrFromInt(addr & ~page_mask_4k);
    return ptr[0..num_table_entries];
}

fn getLv4Table(cr3: Phys) []Lv4Entry {
    return getTable(Lv4Entry, cr3);
}

fn getLv3Table(lv3_paddr: Phys) []Lv3Entry {
    return getTable(Lv3Entry, lv3_paddr);
}

fn getLv2Table(lv2_paddr: Phys) []Lv2Entry {
    return getTable(Lv2Entry, lv2_paddr);
}

fn getLv1Table(lv1_paddr: Phys) []Lv1Entry {
    return getTable(Lv1Entry, lv1_paddr);
}

fn getEntry(T: type, vaddr: Virt, paddr: Phys) *T {
    const table = getTable(T, paddr);
    const shift = switch (T) {
        Lv4Entry => lv4_shift,
        Lv3Entry => lv3_shift,
        Lv2Entry => lv2_shift,
        Lv1Entry => lv1_shift,
        else => @compileError("Unsupported type"),
    };
    return &table[(vaddr >> shift) & index_mask];
}

fn getLv4Entry(addr: Virt, cr3: Phys) *Lv4Entry {
    return getEntry(Lv4Entry, addr, cr3);
}

fn getLv3Entry(addr: Virt, lv3tbl_paddr: Phys) *Lv3Entry {
    return getEntry(Lv3Entry, addr, lv3tbl_paddr);
}

fn getLv2Entry(addr: Virt, lv2tbl_paddr: Phys) *Lv2Entry {
    return getEntry(Lv2Entry, addr, lv2tbl_paddr);
}

fn getLv1Entry(addr: Virt, lv1tbl_paddr: Phys) *Lv1Entry {
    return getEntry(Lv1Entry, addr, lv1tbl_paddr);
}

/// Make level-4 page table writable.
/// The page tables prepared by the bootloader are marked as read-only.
/// To modify page mappings, this function duplicates the level-4 page table
/// and load the new level-4 page table to CR3.
pub fn setLv4Writable(bs: *BootServices) PageError!void {
    var new_lv4ptr: [*]Lv4Entry = undefined;
    const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&new_lv4ptr));
    if (status != .Success) return PageError.NoMemory;

    const new_lv4tbl = new_lv4ptr[0..num_table_entries];
    const lv4tbl = getLv4Table(am.readCr3());
    @memcpy(new_lv4tbl, lv4tbl);

    am.loadCr3(@intFromPtr(new_lv4tbl.ptr));
}

/// Change the attribute of the 4KiB page.
pub fn changeMap4k(virt: Virt, attr: PageAttribute) PageError!void {
    if (virt & 0xFFF != 0) return PageError.InvalidAddress;
    if (!isCanonical(virt)) return PageError.NotCanonical;

    const rw = switch (attr) {
        .read_only, .executable => false,
        .read_write => true,
    };
    const xd = attr != .executable;

    const lv4ent = getLv4Entry(virt, am.readCr3());
    if (!lv4ent.present) return PageError.NotPresent;
    const lv3ent = getLv3Entry(virt, lv4ent.address());
    if (!lv3ent.present) return PageError.NotPresent;
    const lv2ent = getLv2Entry(virt, lv3ent.address());
    if (!lv2ent.present) return PageError.NotPresent;
    const lv1ent = getLv1Entry(virt, lv2ent.address());
    if (!lv1ent.present) return PageError.NotPresent;

    lv1ent.rw = rw;
    lv1ent.xd = xd;
    am.flushTlbSingle(virt);
}

/// Maps 4KiB page at the given virtual address to the given physical address.
/// If the mapping already exists, this function modifies the existing mapping.
/// If the mapping does not exist, this function creates a new mapping,
/// where new memory is allocated for page tables using BootServices.
/// New page tables are allocated as 4KiB BootServicesData pages.
pub fn map4kTo(virt: Virt, phys: Phys, attr: PageAttribute, bs: *BootServices) PageError!void {
    if (virt & page_mask_4k != 0) return PageError.InvalidAddress;
    if (phys & page_mask_4k != 0) return PageError.InvalidAddress;
    if (!isCanonical(virt)) return PageError.NotCanonical;

    const rw = switch (attr) {
        .read_only, .executable => false,
        .read_write => true,
    };
    const xd = attr == .executable;

    const lv4ent = getLv4Entry(virt, am.readCr3());
    if (!lv4ent.present) try allocateNewTable(Lv4Entry, lv4ent, bs);

    const lv3ent = getLv3Entry(virt, lv4ent.address());
    if (!lv3ent.present) try allocateNewTable(Lv3Entry, lv3ent, bs);

    const lv2ent = getLv2Entry(virt, lv3ent.address());
    if (!lv2ent.present) try allocateNewTable(Lv2Entry, lv2ent, bs);

    const lv1ent = getLv1Entry(virt, lv2ent.address());
    if (lv1ent.present) return PageError.AlreadyMapped;
    var new_lv1ent = Lv1Entry.newMapPage(phys, true);

    new_lv1ent.rw = rw;
    new_lv1ent.xd = xd;
    lv1ent.* = new_lv1ent;
    // No need to flush TLB because the page was not present before.
}

/// Allocate new page tables and update the given page table entry.
fn allocateNewTable(T: type, entry: *T, bs: *BootServices) PageError!void {
    var ptr: Phys = undefined;
    const status = bs.allocatePages(.AllocateAnyPages, .BootServicesData, 1, @ptrCast(&ptr));
    if (status != .Success) return PageError.NoMemory;

    clearPage(ptr);
    entry.* = T.newMapTable(@ptrFromInt(ptr), true);
}

/// Zero-clear the given 4KiB page.
fn clearPage(addr: Phys) void {
    const page_ptr: [*]u8 = @ptrFromInt(addr);
    @memset(page_ptr[0..page_size_4k], 0);
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
        /// Indicates wheter software has written to this page.
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
        /// Ignored
        restart: bool = false,
        /// When the entry maps a page, physical address of the page.
        /// When the entry references a page table, physical address of the page table.
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
                .phys = @truncate(@intFromPtr(table) >> page_shift_4k),
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
