//! A simple Berkley Packet Filter (BPF) abstraction for the Interface Sockets in `connect.zig`.

const std = @import("std");
const fs = std.fs;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const BPF = os.linux.BPF;
const process = std.process;
const time = std.time;

const lib = @import("zinglib.zig");


/// An abstraction over BPF Filters
pub const Filter = struct{
    /// File descriptor of this Filter's Map.
    map: os.linux.fd_t,


    /// Initialize this Filter
    pub fn init() !@This() {
        const map = try BPF.map_create(.hash, 4, 8, 2);
        try BPF.map_update_elem(map, "6", "0", 0);

        const prog: []BPF.Insn = &.{
            BPF.Insn.mov(6, 1),
            BPF.Insn.ld_abs(BPF.B, 14 + 9),
            BPF.Insn.stx(BPF.W, 10, 0, -4),
            
            BPF.Insn.exit(),
        };



    }
};
