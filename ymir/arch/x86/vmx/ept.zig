//! Extended Page Table support.
//! cf. SDM Vol.3C 29.3.

const std = @import("std");
const log = std.log.scoped(.ept);
const Allocator = std.mem.Allocator;

const ymir = @import("ymir");
const mem = ymir.mem;
const Phys = mem.Phys;
const Virt = mem.Virt;

const page_mask_4k = mem.page_mask_4k;
const page_mask_2mb = mem.page_mask_2mb;
const page_shift_4k = mem.page_shift_4k;
const page_size_4k = mem.page_size_4k;
const page_size_2mb = mem.page_size_2mb;
const page_size_1gb = mem.page_size_1gb;

const v2p = ymir.mem.virt2phys;
const p2v = ymir.mem.phys2virt;

/// Shift in bits to extract the level-4 index from a guest physical address.
const lv4_shift = 39;
/// Shift in bits to extract the level-3 index from a guest physical address.
const lv3_shift = 30;
/// Shift in bits to extract the level-2 index from a guest physical address.
const lv2_shift = 21;
/// Shift in bits to extract the level-1 index from a guest physical address.
const lv1_shift = 12;
/// Mask to extract page entry index from a shifted guest physical address.
const index_mask = 0x1FF;

/// Number of entries in a page table.
const num_table_entries: usize = 512;

/// Init guest EPT.
pub fn initEpt(
    /// Guest physical address to map.
    guest_start: Phys,
    /// Host physical address to map.
    host_start: Phys,
    /// Size in bytes of the memory region to map.
    size: usize,
    /// Page allocator.
    page_allocator: Allocator,
) ![]Lv4EptEntry {
    if (size & page_mask_2mb != 0) {
        @panic("Requested end adderss is not 2MiB page aligned.");
    }
    if (size > page_size_1gb * num_table_entries) {
        @panic("Requested end address is too large.");
    }

    const lv4_tbl = try initLv4Table(page_allocator);
    log.debug("EPT Level4 Table @ {X:0>16}", .{@intFromPtr(lv4_tbl.ptr)});

    for (0..size / page_size_2mb) |i| {
        try map2m(
            guest_start + page_size_2mb * i,
            host_start + page_size_2mb * i,
            lv4_tbl,
            page_allocator,
        );
    }

    return lv4_tbl;
}

/// Maps the given 2MiB host physical memory to the guest physical memory.
fn map2m(
    guest_phys: Phys,
    host_phys: Phys,
    lv4tbl: []Lv4EptEntry,
    page_allocator: Allocator,
) !void {
    const lv4index = (guest_phys >> lv4_shift) & index_mask;
    var lv4ent = &lv4tbl[lv4index];
    if (!lv4ent.present()) {
        const lv3tbl = try initLv3Table(page_allocator);
        lv4ent.* = Lv4EptEntry.new(lv3tbl);
    }

    const lv3tbl = getLv3Table(lv4ent.address());
    const lv3index = (guest_phys >> lv3_shift) & index_mask;
    var lv3ent = &lv3tbl[lv3index];
    if (!lv3ent.present()) {
        const lv2tbl = try initLv2Table(page_allocator);
        lv3ent.* = Lv3EptEntry.new(lv2tbl);
    }

    const lv2tbl = getLv2Table(lv3ent.address());
    const lv2index = (guest_phys >> lv2_shift) & index_mask;
    var lv2ent = &lv2tbl[lv2index];
    if (!lv2ent.present()) {
        lv2ent.* = Lv2EptEntry{
            .map_memory = true,
            .phys = @truncate(host_phys >> page_shift_4k),
        };
    }
}

fn getLv3Table(first_lv3ent_addr: Phys) []Lv3EptEntry {
    const first_lv3ent: [*]Lv3EptEntry = @ptrFromInt(p2v(first_lv3ent_addr));
    return first_lv3ent[0..num_table_entries];
}

fn getLv2Table(first_lv2ent_addr: Phys) []Lv2EptEntry {
    const first_lv2ent: [*]Lv2EptEntry = @ptrFromInt(p2v(first_lv2ent_addr));
    return first_lv2ent[0..num_table_entries];
}

fn initLv4Table(page_allocator: Allocator) ![]Lv4EptEntry {
    const lv4tbl = try page_allocator.alloc(Lv4EptEntry, num_table_entries);
    for (0..lv4tbl.len) |i| {
        lv4tbl[i].read = false;
        lv4tbl[i].write = false;
        lv4tbl[i].exec_super = false;
        lv4tbl[i].map_memory = false;
        lv4tbl[i].type = .uncacheable;
    }

    return lv4tbl;
}

fn initLv3Table(page_allocator: Allocator) ![]Lv3EptEntry {
    const lv3tbl = try page_allocator.alloc(Lv3EptEntry, num_table_entries);
    for (0..lv3tbl.len) |i| {
        lv3tbl[i].read = false;
        lv3tbl[i].write = false;
        lv3tbl[i].exec_super = false;
        lv3tbl[i].map_memory = false;
        lv3tbl[i].type = .uncacheable;
    }

    return lv3tbl;
}

fn initLv2Table(page_allocator: Allocator) ![]Lv2EptEntry {
    const lv2tbl = try page_allocator.alloc(Lv2EptEntry, num_table_entries);
    for (0..lv2tbl.len) |i| {
        lv2tbl[i].read = false;
        lv2tbl[i].write = false;
        lv2tbl[i].exec_super = false;
        lv2tbl[i].map_memory = false;
        lv2tbl[i].type = .uncacheable;
    }

    return lv2tbl;
}

const MemoryType = enum(u3) {
    uncacheable = 0,
    write_back = 6,
};

/// Level-4 (First) EPT entry, PML4E.
/// This entry can map 512GiB region or reference a level-3 EPT table.
const Lv4EptEntry = packed struct(u64) {
    /// Whether reads are allowed.
    read: bool = true,
    /// Whether writes are allowed.
    write: bool = true,
    /// If "mode-based execute control for EPT" is 0, execute access.
    /// If that field is 1, execute access for supervisor-mode linear address.
    exec_super: bool = true,
    /// EPT memory type.
    /// ReservedZ when the entry maps a 1GiB page.
    type: MemoryType = .uncacheable,
    /// Ignore PAT memory type.
    ignore_pat: bool = false,
    /// If true, this entry maps an memory, Otherwise, this references a level-3 EPT table.
    map_memory: bool,
    /// If EPTP[6] is 1, accessed flag. Otherwise, ignored.
    accessed: bool = false,
    // If EPTP[6] is 1, dirty flag. Otherwise, ignored.
    dirty: bool = false,
    /// Execute access for user-mode linear address.
    exec_user: bool = true,
    /// Ignored
    _ignored2: u1 = 0,
    /// 4KB aligned address of the level-3 EPT table.
    phys: u52,

    pub fn present(self: Lv4EptEntry) bool {
        return self.read or self.write or self.exec_super;
    }

    /// Create a new Level-4 EPT entry that references a level-3 EPT table.
    pub fn new(lv3tbl: []Lv3EptEntry) Lv4EptEntry {
        const phys_lv3tbl = v2p(lv3tbl.ptr);
        return Lv4EptEntry{
            .map_memory = false,
            .type = .uncacheable,
            .phys = @truncate(phys_lv3tbl >> page_shift_4k),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv4EptEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

/// Level-3 EPT entry, PDPTE.
/// This entry can map 1GiB region or reference a level-2 EPT table.
const Lv3EptEntry = packed struct(u64) {
    /// Whether reads are allowed.
    read: bool = true,
    /// Whether writes are allowed.
    write: bool = true,
    /// If "mode-based execute control for EPT" is 0, execute access.
    /// If that field is 1, execute access for supervisor-mode linear address.
    exec_super: bool = true,
    /// EPT memory type.
    /// ReservedZ when the entry maps a 1GiB page.
    type: MemoryType = .uncacheable,
    /// Ignore PAT memory type.
    ignore_pat: bool = false,
    /// If true, this entry maps an memory, Otherwise, this references a level-2 EPT table.
    map_memory: bool,
    /// If EPTP[6] is 1, accessed flag. Otherwise, ignored.
    accessed: bool = false,
    // If EPTP[6] is 1, dirty flag. Otherwise, ignored.
    dirty: bool = false,
    /// Execute access for user-mode linear address.
    exec_user: bool = true,
    /// Ignored
    _ignored2: u1 = 0,
    /// 4KB aligned address of the level-2 EPT table, or 1GiB aligned address of the memory.
    phys: u52,

    pub fn present(self: Lv3EptEntry) bool {
        return self.read or self.write or self.exec_super;
    }

    /// Create a new Level-3 EPT entry that references a level-2 EPT table.
    pub fn new(lv2tbl: []Lv2EptEntry) Lv3EptEntry {
        const phys_lv2tbl = v2p(lv2tbl.ptr);
        return Lv3EptEntry{
            .map_memory = false,
            .type = .uncacheable,
            .phys = @truncate(phys_lv2tbl >> page_shift_4k),
        };
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv3EptEntry) Phys {
        return @as(u64, @intCast(self.phys)) << page_shift_4k;
    }
};

/// Level-2 EPT entry.
/// This entry can map 2MiB region or reference a level-1 EPT table.
const Lv2EptEntry = packed struct(u64) {
    /// Whether reads are allowed.
    read: bool = true,
    /// Whether writes are allowed.
    write: bool = true,
    /// If "mode-based execute control for EPT" is 0, execute access.
    /// If that field is 1, execute access for supervisor-mode linear address.
    exec_super: bool = true,
    /// EPT memory type.
    /// ReservedZ when the entry maps a 2-MByte page.
    type: MemoryType = .write_back,
    /// Ignore PAT memory type.
    ignore_pat: bool = false,
    /// If true, this entry maps an memory, Otherwise, this references a level-2 EPT table.
    map_memory: bool,
    /// If EPTP[6] is 1, accessed flag. Otherwise, ignored.
    accessed: bool = false,
    // If EPTP[6] is 1, dirty flag. Otherwise, ignored.
    dirty: bool = false,
    /// Execute access for user-mode linear address.
    exec_user: bool = true,
    /// Ignored
    _ignored2: u1 = 0,
    /// 4KB aligned address of the level-1 EPT table, or 2MiB aligned address of the memory.
    phys: u52,

    pub fn present(self: Lv2EptEntry) bool {
        return self.read or self.write or self.exec_super;
    }

    /// Get the physical address pointed by this entry.
    pub inline fn address(self: Lv2EptEntry) Phys {
        return @as(u64, @intCast(self.phys_pdpt)) << page_shift_4k;
    }
};

/// Level-1 EPT entry.
/// This entry can map 4KiB region.
const Lv1EptEntry = packed struct(u64) {
    /// Whether reads are allowed.
    read: bool = true,
    /// Whether writes are allowed.
    write: bool,
    /// If "mode-based execute control for EPT" is 0, execute access.
    /// If that field is 1, execute access for supervisor-mode linear address.
    exec_super: bool,
    /// EPT memory type.
    /// ReservedZ when the entry maps a 4KiB page.
    type: MemoryType = .write_back,
    /// Ignore PAT memory type.
    ignore_pat: bool = false,
    /// If true, this entry maps an memory, Otherwise, this references a level-2 EPT table.
    map_memory: bool,
    /// If EPTP[6] is 1, accessed flag. Otherwise, ignored.
    accessed: bool = false,
    // If EPTP[6] is 1, dirty flag. Otherwise, ignored.
    dirty: bool = false,
    /// Execute access for user-mode linear address.
    exec_user: bool,
    /// Ignored
    _ignored2: u1 = 0,
    /// 4KB aligned address of memory region.
    phy: u52,
};

/// Extended Page Table Pointer.
/// cf. SDM Vol.3C 25.6.11.
pub const Eptp = packed struct(u64) {
    /// Memory type.
    type: MemoryType = .write_back,
    /// EPT page-walk length.
    level: PageLevel = .four,
    /// Enable dirty and accessed flags for EPT.
    enable_ad: bool = true,
    /// Enable enforcement of access rights for supervisor shadow-stack pages.
    enable_ar: bool = false,
    /// Reserved.
    _reserved1: u4 = 0,
    /// 4KB aligned address of the Level-4 EPT table.
    phys: u52,

    pub fn new(lv4tbl: []Lv4EptEntry) Eptp {
        return Eptp{
            .phys = @truncate(v2p(lv4tbl.ptr) >> page_shift_4k),
        };
    }

    const PageLevel = enum(u3) {
        four = 3,
        five = 4,
    };
};
