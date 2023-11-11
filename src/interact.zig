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

const BUF_SIZE = 4096;

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

    // Run the Start Function (if applicable)
    if (ia_fns.start_fn) |startFn| try startFn(alloc, fn_ctx);

    // Receive Datagrams and React to them (if applicable)
    var dg_count: u32 = 0;
    const infinite_dgs: bool = ia_config.recv_dgs_max == 0;
    // - Multi-Threaded
    if (ia_config.multithreaded) {
        log.debug("Running Multi-Threaded", .{});
        var recv_buf = try InteractBuffer.init(alloc);
        var recv_thread = try std.Thread.spawn(
            .{ .allocator = alloc },
            recv.recvDatagramThread,
            .{
                alloc,
                recv_sock,
                &recv_buf,
                ia_config.recv_dgs_max,
            }
        );
        defer recv_thread.join();

        while (
            if (!infinite_dgs) dg_count < ia_config.recv_dgs_max
            else true
        ) {
            if (ia_fns.react_fn) |reactFn| {
                if (recv_buf.pop()) |datagram| {
                    log.debug("Spawning Thread.", .{});
                    var thread = try std.Thread.spawn(
                        .{ .allocator = alloc },
                        reactFn.*,
                        .{ alloc, fn_ctx, datagram }
                    );
                    thread.join();
                    dg_count += 1;
                }
            }
        }
    }
    // - Single Threaded
    else {
        log.debug("Running Single-Threaded", .{});
        while (
            if (!infinite_dgs) dg_count < ia_config.recv_dgs_max
            else true
        ) : (dg_count += 1) {
            const datagram = recv.recvDatagram(alloc, recv_sock) catch |err| switch (err) {
                error.UnimplementedType => continue,
                else => return err,
            };
            if (ia_fns.react_fn) |reactFn| try reactFn(alloc, fn_ctx, datagram);
        }
    }
    // Run the End Function (if applicable)
    if (ia_fns.end_fn) |endFn| try endFn(alloc, fn_ctx);
}

/// A Thread Safe, Array List based Buffer for Interactions.
pub const InteractBuffer = struct{
    /// The ArrayList containing all Datagrams.
    list: std.ArrayList(Datagrams.Full),
    /// A Mutex Lock for this Interaction Buffer.
    mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// Initialize a new InteractionBuffer with the provided Allocator (`alloc`).
    pub fn init(alloc: mem.Allocator) !@This(){
        return .{
            .list = std.ArrayList(Datagrams.Full).init(alloc),
        };
    }

    /// Push a Datagram (`datagram`) to this Interaction Buffer.
    pub fn push(self: *@This(), datagram: Datagrams.Full) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.list.insert(0, datagram);
    }

    /// Pop and return a Datagram from this Interaction Buffer or null if the ArrayList is empty.
    pub fn pop(self: *@This()) ?Datagrams.Full {
        if (self.list.items.len == 0) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.list.pop();
    }
};
