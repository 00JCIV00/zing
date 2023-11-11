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
pub const InteractConfig = struct{
    /// Max number of Datagrams to be processed.
    /// Setting this to 0 will allow for infinite loops
    recv_dgs_max: u32 = 10,
    /// Run Reaction Functions in their own Thread.
    multithreaded: bool = true,
};

/// Interaction Functions.
/// **Comptime Only!**
pub const InteractFunctions = struct{
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
};

/// Interact with a Network using the provided Allocator (`alloc`), Function Context (`fn_ctx`), and Interaction Config (`config`).
pub fn interact(
    alloc: mem.Allocator, 
    fn_ctx: anytype, 
    sock_config: conn.IFSocket.IFSocketInitConfig, 
    ia_config: InteractConfig, 
    comptime ia_fns: InteractFunctions
) !void {
    // Setup Sockets
    var recv_sock = try conn.IFSocket.init(sock_config);
    defer recv_sock.close();

    // Setup for Receiving Datagrams
    const buf_size = 4096;
    var recv_buf = try alloc.alloc(
        [buf_size]u8, 
        if (ia_config.recv_dgs_max > 0) ia_config.recv_dgs_max
        else 100,
    );
    defer alloc.free(recv_buf);

    // Run the Start Function (if applicable)
    if (ia_fns.start_fn) |startFn| try startFn(alloc, fn_ctx);

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
            recv_buf = try alloc.alloc([buf_size]u8, 100);
        }
        dg_count += 1;
        dg_idx = if (infinite_dgs) dg_count % 100 else dg_count;
    }) {
        const datagram = recv.recvDatagram(alloc, recv_sock) catch |err| switch (err) {
            error.UnimplementedType => continue,
            else => return err,
        };
        if (ia_fns.react_fn) |reactFn| {
            if (!ia_config.multithreaded) try reactFn(alloc, fn_ctx, datagram)
            else {
                log.debug("Spawning Thread.", .{});
                //thread_pool.spawn(reactFn, .{ alloc, fn_ctx, datagram });
                var thread = try std.Thread.spawn(
                    .{ .allocator = alloc },
                    reactFn.*,
                    .{ alloc, fn_ctx, datagram }
                );
                thread.join();
            }
        }
    }


    // Run the End Function (if applicable)
    if (ia_fns.end_fn) |endFn| try endFn(alloc, fn_ctx);
}
