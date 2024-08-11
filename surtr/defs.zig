//! This file defines structures shared among Surtr and Ymir.

/// Magic number to check if the boot info is valid.
pub const surtr_magic: usize = 0xDEADBEEF_CAFEBABE;

/// Boot information.
/// This struct is passed from the bootloader to the kernel in Win64 calling convention.
pub const BootInfo = extern struct {
    magic: usize = surtr_magic,
};
