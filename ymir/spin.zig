const is_test = @import("builtin").is_test;

const atomic = @import("std").atomic;

const ymir = @import("ymir");
const arch = ymir.arch;

pub const SpinLock = struct {
    const State = atomic.Value(bool);

    /// State of the spin lock.
    /// true when locked, false when unlocked.
    _state: State = State.init(false),

    /// Lock the spin lock.
    pub inline fn lock(self: *SpinLock) void {
        atomic.spinLoopHint();
        while (self._state.cmpxchgWeak(
            false,
            true,
            .acq_rel,
            .monotonic,
        ) != null) {
            arch.pause();
        }
    }

    /// Lock the spin lock and disable IRQ.
    /// Must be paired with `unlockRestoreIrq()`.
    pub fn lockSaveIrq(self: *SpinLock) u16 {
        if (!is_test) {
            const mask = arch.pic.getIrqMask();
            arch.pic.setIrqMask(0xFFFF);
            lock(self);
            return mask;
        } else {
            lock(self);
            return 0;
        }
    }

    /// Unlock the spin lock.
    pub inline fn unlock(self: *SpinLock) void {
        self._state.store(false, .release);
    }

    /// Unlock the spin lock and restore IRQ mask.
    pub fn unlockRestoreIrq(self: *SpinLock, mask: u16) void {
        self.unlock();
        if (!is_test) {
            arch.pic.setIrqMask(mask);
        }
    }
};
