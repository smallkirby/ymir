const is_test = @import("builtin").is_test;

const ymir = @import("ymir");
const arch = ymir.arch;

pub const SpinLock = struct {
    _lock: State = .unlocked,

    pub const State = enum(u1) {
        unlocked = 0,
        locked = 1,
    };

    /// Lock the spin lock.
    pub inline fn lock(self: *SpinLock) void {
        while (@cmpxchgWeak(
            @TypeOf(self._lock),
            &self._lock,
            .unlocked,
            .locked,
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
        _ = @cmpxchgWeak(
            @TypeOf(self._lock),
            &self._lock,
            .locked,
            .unlocked,
            .acq_rel,
            .monotonic,
        );
    }

    /// Unlock the spin lock and restore IRQ mask.
    pub fn unlockRestoreIrq(self: *SpinLock, mask: u16) void {
        self.unlock();
        if (!is_test) {
            arch.pic.setIrqMask(mask);
        }
    }
};
