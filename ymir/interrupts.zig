//! User-defined interrupts.

const arch = @import("ymir").arch;

const base = arch.intr.num_system_exceptions;

pub const pic_timer = 0 + base;
pub const pic_keyboard = 1 + base;
pub const pic_secondary = 2 + base;
pub const pic_serial2 = 3 + base;
pub const pic_serial1 = 4 + base;
