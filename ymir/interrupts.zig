//! User-defined interrupts.

const arch = @import("ymir").arch;

/// The start of user-defined interrupts number.
pub const user_intr_base = arch.intr.num_system_exceptions;

pub const pic_timer = 0 + user_intr_base;
pub const pic_keyboard = 1 + user_intr_base;
pub const pic_secondary = 2 + user_intr_base;
pub const pic_serial2 = 3 + user_intr_base;
pub const pic_serial1 = 4 + user_intr_base;
