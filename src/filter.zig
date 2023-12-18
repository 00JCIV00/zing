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
const Addresses = lib.Addresses;


const load_ether = BPF.Insn{
    .code = 0x28,
    .dst = 0,
    .src = 0,
    .off = 12,
    .imm = 0x0000000c,
};

/// An abstraction over BPF Filters
pub const Filter = struct{
    /// File descriptor of this Filter's Map.
    map: os.linux.fd_t,

    /// Base Instructions 
    bpf_instructions: []BPF.Insn = &.{}, 

    /// Initialize this Filter
    pub fn init() !@This() {
        const ip = try Addresses.IPv4.fromStr("192.168.0.1");
        const port: u32 = 80;
        const map = try BPF.map_create(.hash, 4, 8, 2);
        try BPF.map_update_elem(map, "6", "0", 0);

        //const prog: []BPF.Insn = &.{
        //    BPF.Insn.mov(6, 1),
        //    BPF.Insn.ld_abs(BPF.B, 14 + 9),
        //    BPF.Insn.stx(BPF.W, 10, 0, -4),
        //    
        //    BPF.Insn.exit(),
        //};
        const prog: []BPF.Insn = &.{
            BPF.Insn{ 0x28, 0, 0, 12, 0x0000000c },
            BPF.Insn{ 0x15, 0, 1, 0, 0x00000006 },
            BPF.Insn{ 0x20, 0, 0, 12, @bitCast(ip) },
            BPF.Insn{ 0x20, 0, 0, 0, 0x0000000e },
            BPF.Insn{ 0x15, 0, 3, 0, port },

            BPF.Insn{ 0x6, 0, 0, 0, 0xFFFF },
            BPF.Insn{ 0x6, 0, 0, 0, 0x0 },
            
            BPF.Insn.exit(),
        };
        _ = prog;



    }
};
