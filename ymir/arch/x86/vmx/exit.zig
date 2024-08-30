/// Exit qualification for I/O instructions.
/// cf. SDM Vol.3C Table 28-5.
pub const QualIo = packed struct(u64) {
    /// Size of access.
    size: Size,
    /// Direction of the attempted access.
    direction: Direction,
    /// String instruction.
    string: bool,
    /// Rep prefix.
    rep: bool,
    /// Operand encoding.
    operand_encoding: OperandEncoding,
    /// Not used.
    _reserved2: u9,
    /// Port number.
    port: u16,
    /// Not used.
    _reserved3: u32,

    const Size = enum(u3) {
        /// Byte.
        byte = 0,
        /// Word.
        word = 1,
        /// Dword.
        dword = 3,
    };

    const Direction = enum(u1) {
        out = 0,
        in = 1,
    };

    const OperandEncoding = enum(u1) {
        /// I/O instruction uses DX register as port number.
        dx = 0,
        /// I/O instruction uses immediate value as port number.
        imm = 1,
    };
};

/// Exit qualification for EPT violations.
/// cf. SDM Vol.3C Table 28-7.
pub const QualEptViolation = packed struct(u64) {
    /// The violation was data read.
    read: bool,
    /// The violation was data write.
    write: bool,
    /// The violation was instruction fetch.
    fetch: bool,
    /// The page is readable.
    readable: bool,
    /// The page is writable.
    writable: bool,
    /// The page is executable.
    executable: bool,
    /// The page is executable for user-mode linear addresses.
    /// Undefined if "mode-based execute control" is 0.
    executable_user: bool,
    /// Guest linear-address field is valid.
    valid_linear: bool,
    /// The violation occurred during a guest page table walk.
    during_walk: bool,
    ///
    linear_user: bool,
    ///
    rw: bool,
    ///
    exec_disabled: bool,
    ///
    nmi_unblocking: bool,
    ///
    shadow_stack: bool,
    ///
    b60: bool,
    ///
    verification: bool,
    ///
    trace: bool,
    /// Reserved.
    reserved: u47,
};
