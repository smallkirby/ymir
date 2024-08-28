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
