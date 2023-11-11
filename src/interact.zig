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
const recv = lib.recv;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

/// Interaction Config.
/// **Comptime Only!**
pub const InteractConfig = struct{
    /// Receive Buffer Max size. (Max 4096)
    recv_buf_max: u13 = 4096,

    /// Max number of Datagrams to receive one Batch of CQEs.
    /// TODO: Figure out if IO_Uring can be used for AF_PACKET, SOCK_RAW, ETH_P_ALL sockets.
    recv_batch_max: u32 = 1,

    /// Max number of Datagrams to be processed.
    /// Setting this to 0 will allow for infinite loops
    recv_dgs_max: u32 = 10,

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
pub fn interact(alloc: mem.Allocator, fn_ctx: anytype, sock_config: conn.IFSocket.IFSocketInitConfig, comptime ia_config: InteractConfig) !void {
    // Setup Sockets
    var recv_sock = try conn.IFSocket.init(sock_config);
    defer recv_sock.close();

    // Setup IO_Uring
    var recv_io = try os.linux.IO_Uring.init(ia_config.recv_buf_max, 0);
    defer recv_io.deinit();
    var recv_cqes = try alloc.alloc(os.linux.io_uring_cqe, ia_config.recv_buf_max);
    defer alloc.free(recv_cqes);

    // Run the Start Function (if applicable)
    if (ia_config.start_fn) |startFn| try startFn(alloc, fn_ctx);

    // Setup for Receiving Datagrams
    //var recv_buf: [4096]u8 = .{ 0 } ** 4096;
    //var recv_buf = std.RingBuffer.init(alloc, 4096);
    var recv_buf = try alloc.alloc(
        [ia_config.recv_buf_max]u8, 
        if (ia_config.recv_dgs_max > 0) ia_config.recv_dgs_max
        else 100,
    );
    defer alloc.free(recv_buf);

    //const l2_type: meta.Tag(Datagrams.Layer2Header) = switch (recv_sock.hw_fam) {
    //    consts.ARPHRD_ETHER => .eth,
    //    else => return error.UnimplementedType,
    //};

    // Receive Datagrams and React to them (if applicable)
    var dg_count: u32 = 0;
    var dg_idx: u32 = 0;
    const infinite_dgs: bool = ia_config.recv_dgs_max == 0;
    while (
        if (!infinite_dgs) dg_count < ia_config.recv_dgs_max
        else true
    ) : ({
        if (infinite_dgs and dg_idx == 99) {
            alloc.free(recv_buf);
            recv_buf = try alloc.alloc([ia_config.recv_buf_max]u8, 100);
        }
        dg_count += 1;
        dg_idx = if (infinite_dgs) dg_count % 100 else dg_count;
    }) {
        const datagram = recv.recvDatagram(alloc, recv_sock) catch |err| switch (err) {
            error.UnimplementedType => continue,
            else => return err,
        };
        if (ia_config.react_fn) |reactFn| try reactFn(alloc, fn_ctx, datagram);
    }

    // TODO: Figure out IO_Uring support.
    // Receive Datagrams and React to them (if applicable)
    //var cqe_count: u32 = 0;
    //while (
    //    if (ia_config.recv_dgs_max > 0) cqe_count < ia_config.recv_dgs_max
    //    else true
    //) {
    //    //os.linux.io_uring_prep_recv(try recv_io.get_sqe(), recv_sock.desc, recv_buf[0..1518], 0);
    //    _ = try recv_io.recv(0, recv_sock.desc, .{ .buffer = recv_buf[0..] }, 0);
    //    const sqe_submit = try recv_io.submit_and_wait(1);//ia_config.recv_batch_max);
    //    log.debug("SQEs Submitted: {d}.", .{ sqe_submit });

    //    if (recv_io.cq_ready() == 0) continue;


    //    const num_cqes = try recv_io.copy_cqes(recv_cqes, ia_config.recv_batch_max);
    //    log.debug("Processing {d} CQE(s)...", .{ num_cqes });
    //    for (recv_cqes[0..num_cqes], 0..) |cqe, idx| {
    //        log.debug("- Checking CQE #{d}...", .{ idx });
    //      if (cqe.res == 0) {
    //          log.debug("- No bytes received.", .{}); 
    //          continue;
    //      }
    //      if (cqe.res < 0) {
    //          const errno = cqe.res * -1;
    //          log.err("Error receiving bytes: #{d} - {s}\n{any}", .{ 
    //              errno, 
    //              @tagName(@as(os.linux.E, @enumFromInt(errno))),
    //              cqe
    //          });
    //          return error.ReceiveError;
    //      }
    //      log.debug("Received {d}B Datagram.", .{ cqe.res });
    //      const datagram = try Datagrams.Full.fromBytes(alloc, recv_buf[0..], l2_type);
    //      if (ia_config.react_fn) |reactFn| try reactFn(alloc, fn_ctx, datagram);
    //    }
    //    log.debug("Processed {d} CQE(s).", .{ num_cqes });

    //}

    // Run the End Function (if applicable)
    if (ia_config.end_fn) |endFn| try endFn(alloc, fn_ctx);
}
