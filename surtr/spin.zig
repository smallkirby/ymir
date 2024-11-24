const is_test = @import("builtin").is_test;

const atomic = @import("std").atomic;

fn pause() void {
    asm volatile ("pause" ::: "memory");
}

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
            atomic.spinLoopHint();
        }
    }

    /// Unlock the spin lock.
    pub inline fn unlock(self: *SpinLock) void {
        self._state.store(false, .release);
    }
};
