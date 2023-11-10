//! Functions for doing Network Interactions.

const std = @import("std");
const fs = std.fs;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;
const time = std.time;

const lib = @import("zinglib.zig");
const conn = lib.connect;
const consts = lib.constants;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

/// Interaction Config
pub const InteractConfig = struct{
    /// Receive Socket Config.
    recv_sock_config: conn.IFSocket.IFSocketInitConfig = .{},

    /// RingBuffer Max size. (Max 4096)
    ring_buf_max: u13 = 4096,

    /// Max number of Datagrams to receive one Batch of CQEs.
    recv_batch_max: u32 = 1,

    /// A Function to be called at the Start of an Interaction.
    ///
    /// Parameters:
    /// 1. Allocator
    /// 2. Context
    start_fn: ?*const fn(mem.Allocator, anytype) anyerror!void = null,
    
    /// A Function to be called in Reaction to each Datagram received during an Interaction.
    ///
    /// Parameters:
    /// 1. Allocator
    /// 2. Context - Must be a Nullable Pointer to a Type (`*T`).
    /// 3. Received Datagram
    react_fn: ?*const fn(mem.Allocator, anytype, Datagrams.Full) anyerror!void = null,

    /// A Function to be called at the End of an Interaction.
    ///
    /// Parameters:
    /// 1. Allocator
    /// 2. Context
    end_fn: ?*const fn(mem.Allocator) anyerror!void = null,

    // A Context object to be used in Function calls.
    //fn_ctx: ?*anyopaque = null,
};

/// Interact with a Network using the provided Allocator (`alloc`), Function Context (`fn_ctx`), and Interaction Config (`config`).
pub fn interact(alloc: mem.Allocator, fn_ctx: anytype, comptime config: InteractConfig) !void {
    // Setup Sockets
    var recv_sock = try conn.IFSocket.init(config.recv_sock_config);
    defer recv_sock.close();

    // Setup IO_Uring
    var recv_io = try os.linux.IO_Uring.init(config.ring_buf_max, 0);
    defer recv_io.deinit();
    var recv_cqes = try alloc.alloc(os.linux.io_uring_cqe, config.ring_buf_max);
    defer alloc.free(recv_cqes);

    // Run the Start Function (if applicable)
    if (config.start_fn) |startFn| try startFn(alloc, fn_ctx);

    // Setup for Receiving Datagrams
    var recv_buf: [4096]u8 = .{ 0 } ** 4096;
    //var recv_buf = std.RingBuffer.init(alloc, 4096);
    os.linux.io_uring_prep_recv(try recv_io.get_sqe(), recv_sock.ptr, recv_buf[0..], 0);
    _ = try recv_io.submit();

    const l2_type: meta.Tag(Datagrams.Layer2Header) = switch (recv_sock.hw_fam) {
        consts.ARPHRD_ETHER => .eth,
        else => return error.UnimplementedType,
    };

    // Receive Datagrams and React to them (if applicable)
    while (true) {
        const num_cqes = try recv_io.copy_cqes(recv_cqes, config.recv_batch_max);
        log.debug("Processing {d} CQE(s)...", .{ num_cqes });
        for (recv_cqes[0..num_cqes], 0..) |cqe, idx| {
            log.debug("- Checking CQE #{d}...", .{ idx });
            if (cqe.res <= 0) continue;
            log.debug("Received {d}B Datagram.", .{ cqe.res });
            //const datagram = Datagrams.Full.fromBytes(alloc, cqe.user_data, l2_type);
            const datagram = try Datagrams.Full.fromBytes(alloc, recv_buf[0..], l2_type);
            if (config.react_fn) |reactFn| try reactFn(alloc, fn_ctx, datagram);
        }
        log.debug("Processed {d} CQE(s).", .{ num_cqes });

        os.linux.io_uring_prep_recv(try recv_io.get_sqe(), recv_sock.ptr, recv_buf[0..], 0);
        _ = try recv_io.submit();
    }

    // Run the End Function (if applicable)
    if (config.end_fn) |endFn| try endFn(alloc, fn_ctx);
}
