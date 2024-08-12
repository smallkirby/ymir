const ymir = @import("ymir");
const arch = ymir.arch;

const unlocked = 0;
const locked = 1;

pub const SpinLock = struct {
    _lock: u32 = unlocked,

    /// Lock the spin lock.
    pub inline fn lock(self: *SpinLock) void {
        while (@cmpxchgWeak(
            @TypeOf(self._lock),
            &self._lock,
            unlocked,
            locked,
            .acq_rel,
            .monotonic,
        ) != null) {
            arch.pause();
        }
    }

    /// Lock the spin lock and disable interrupts.
    /// Must be paired with `unlockEnableIrq()`.
    pub inline fn lockDisableIrq(self: *SpinLock) void {
        self.lock();
        arch.disableIntr();
    }

    /// Unlock the spin lock.
    pub inline fn unlock(self: *SpinLock) void {
        _ = @cmpxchgWeak(
            @TypeOf(self._lock),
            &self._lock,
            locked,
            unlocked,
            .acq_rel,
            .monotonic,
        );
    }

    /// Unlock the spin lock and enable interrupts.
    pub inline fn unlockEnableIrq(self: *SpinLock) void {
        self.unlock();
        arch.enableIntr();
    }
};
