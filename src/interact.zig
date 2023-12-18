//! Functions for doing Network Interactions.

const std = @import("std");
const ascii = std.ascii;
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
const utils = lib.utils;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

const BUF_SIZE = 4096;

/// A Thread Safe, Array List based Buffer for Interactions.
pub const InteractBuffer = struct{
    /// The ArrayList containing all Datagrams.
    _list: std.ArrayList(Datagrams.Full),
    /// A Mutex Lock for this Interaction Buffer.
    _mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// Initialize a new Interaction Buffer with the provided Allocator (`alloc`).
    pub fn init(alloc: mem.Allocator) @This(){
        return .{
            ._list = std.ArrayList(Datagrams.Full).init(alloc),
        };
    }

    /// Push a Datagram (`datagram`) to this Interaction Buffer.
    pub fn push(self: *@This(), datagram: Datagrams.Full) !void {
        self.*._mutex.lock();
        defer self.*._mutex.unlock();
        try self.*._list.insert(0, datagram);
    }

    /// Pop and return a Datagram from this Interaction Buffer or null if the ArrayList is empty.
    pub fn pop(self: *@This()) ?Datagrams.Full {
        if (self._list.items.len == 0) return null;
        self.*._mutex.lock();
        defer self.*._mutex.unlock();
        return self.*._list.pop();
    }
};

/// A Thread Safe Writer for Interactions.
/// This wraps a provided Writer for thread safety.
///
/// The provided Writer Type (`WriterT`) must have the following functions:
/// - `write()`
/// - `writeAll()`
/// - `print()`
pub fn InteractWriter(comptime WriterT: type) type {
    const required_fns = &.{ "write", "writeAll", "print" };
    for (required_fns) |req_fn| {
        if (!meta.hasFn(WriterT, req_fn)) {
            @compileError(fmt.comptimePrint("The provided Writer Type '{s}' does not implement the required function '{s}()'.", .{
                @typeName(WriterT),
                req_fn,
            }));
        }
    }

    return struct{
        /// The underlying Writer.
        writer: WriterT,
        /// The Read/Write Lock.
        rw_lock: std.Thread.RwLock = std.Thread.RwLock{},

        /// Initialize a new Interaction Writer.
        pub fn init(writer: WriterT) @This(){
            return .{
                .writer = writer,
            };
        }

        /// Write
        pub fn write(self: *@This(), bytes: []const u8) !usize {
            self.*.rw_lock.lock();
            defer self.*.rw_lock.unlock();
            return self.*.writer.write(bytes);
        } 
        /// Write All
        pub fn writeAll(self: *@This(), bytes: []const u8) !void {
            self.*.rw_lock.lock();
            defer self.*.rw_lock.unlock();
            return self.*.writer.writeAll(bytes);
        } 
        /// Print 
        pub fn print(self: *@This(), comptime format: []const u8, args: anytype) !void {
            self.*.rw_lock.lock();
            defer self.*.rw_lock.unlock();
            return self.*.writer.print(format, args);
        } 
    };
}

/// Interaction Config.
pub const InteractConfig = struct{
    /// Max number of Datagrams to be processed for this Interaction.
    /// Setting this to 0 will allow for infinite loops
    recv_dgs_max: u32 = 10,
    /// Batch Size for processing Datagrams.
    /// This is the number of Datagrams that will be sent to a Reaction Function.
    batch_size: u16 = 1,
    /// Run Reaction Functions in their own Thread.
    multithreaded: bool = true,
    /// Start Function Delay.
    /// The time (in ns) from the start of the Receiving Datagrams to when the Start Function is called.
    /// Note, this only works if `multithreaded` is enabled.
    start_fn_delay: u32 = 1 * time.ns_per_s,
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
    end_fn: ?*const fn(mem.Allocator, anytype) anyerror!void = null,
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
    const recv_sock = try conn.IFSocket.init(sock_config);
    defer recv_sock.close();

    // Receive Datagrams and React to them (if applicable)
    var dg_count: u32 = 0;
    const infinite_dgs: bool = ia_config.recv_dgs_max == 0;
    // - Multi-Threaded
    if (ia_config.multithreaded) {
        log.debug("Running Multi-Threaded.", .{});
        var recv_buf = InteractBuffer.init(alloc);
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

        // Run the Start Function (if applicable)
        time.sleep(ia_config.start_fn_delay);
        if (ia_fns.start_fn) |startFn| try startFn(alloc, fn_ctx);

        while (
            if (!infinite_dgs) dg_count < ia_config.recv_dgs_max
            else true
        ) {
            if (ia_fns.react_fn) |reactFn| {
                if (recv_buf.pop()) |datagram| {
                    //log.debug("Datagram Buffer Len: {d}", .{ recv_buf.list.items.len });
                    //log.debug("Spawning Thread.", .{});
                    var thread = try std.Thread.spawn(
                        .{ .allocator = alloc },
                        reactFn.*,
                        .{ alloc, fn_ctx, datagram }
                    );
                    thread.detach();
                    dg_count += 1;
                }
            }
        }
    }
    // - Single Threaded
    else {
        // Run the Start Function (if applicable)
        if (ia_fns.start_fn) |startFn| try startFn(alloc, fn_ctx);

        log.debug("Running Single-Threaded.", .{});
        while (
            if (!infinite_dgs) dg_count < ia_config.recv_dgs_max
            else true
        ) : (dg_count += 1) {
            const datagram = recv.recvDatagram(alloc, recv_sock) catch |err| switch (err) {
                error.UnexpectedlySmallBuffer, 
                error.UnimplementedType => continue,
                else => return err,
            };
            if (ia_fns.react_fn) |reactFn| try reactFn(alloc, fn_ctx, datagram);
        }
    }
    // Run the End Function (if applicable)
    if (ia_fns.end_fn) |endFn| try endFn(alloc, fn_ctx);
}

// Interaction DSL (WIP) ====================================================================================

///// Keywords for Interaction Expressions.
//pub const InteractExprKeywords = struct{
//    /// Top Level
//    pub const TopLevel = enum{
//        IF,
//        DO,
//        NEXT,
//    };
//    /// Boolean
//    pub const Boolean = enum{
//        AND,
//        OR,
//        NOT,
//    };
//    /// Condition
//    pub const Condition = enum{
//        EQUALS,
//        GREATER,
//        LESS,
//    };
//    /// Setter
//    pub const Setter = enum{
//        INC,
//        DEC,
//        SET,
//    };
//};
//
///// Parse Interaction Expressions (`expr`) to manipulate the Outbound Datagram (`out_dg`) based on the Inbound Datagram (`in_dg`).
//pub fn parseInteractExpr(in_dg: Datagrams.Full, out_dg: *Datagrams.Full, expr: []const []const u8) !void {
//    const Keywords = InteractExprKeywords;
//    var idx: u16 = 0;
//    while (idx < expr.len) {
//        const line = expr[idx];
//        if (line.len == 0 or line[0] == '#') continue;
//        switch (meta.stringToEnum(Keywords.TopLevel, line) orelse {
//            log.err("The value '{s}' cannot be used at the Top Level. Only comments ('# ...') or 'IF', 'DO', and 'NEXT' may be used", .{ line });
//            return error.UnexpectedTopLevelValue;
//        }) {
//            .IF => {
//                const do_idx = (utils.indexOfEql([]const u8, expr[idx..], "DO") orelse return error.NoMatchingThen) + idx;
//                const if_expr = expr[idx..do_idx];
//                if (!try parseIfExpr(in_dg, if_expr)) {
//                    idx = (utils.indexOfEql([]const u8, expr[idx..], "NEXT") orelse return) + idx;
//                    continue;
//                }
//
//                idx = do_idx;
//                continue;
//            },
//            .DO => {
//                const next_idx = (utils.indexOfEql([]const u8, expr[idx..], "NEXT") orelse expr[idx..].len) + idx;
//                const do_expr = expr[idx..next_idx];
//                try parseDoBlock(out_dg, do_expr);
//                idx = next_idx;
//            },
//            .NEXT => {},
//        }
//        idx += 1;
//    }
//}
//
///// Parse an "IF" Expression Block.
//fn parseIfBlock(in_dg: Datagrams.Full, block: []const []const u8) !bool {
//    _ = in_dg;
//    _ = block;
//
//    return false;
//}
//
///// Parse an "DO" Expression Block.
//fn parseDoBlock(out_dg: *Datagrams.Full, block: []const []const u8) !void {
//    _ = out_dg;
//    _ = block;
//}
//
///// Parse an "IF" Expression for a Datagram Field.
//fn parseIfExpr(field: anytype, sub_field_names: []const []const u8, expr: []const u8) !bool {
//    const FieldT = @TypeOf(field);
//
//    if (sub_field_names.len == 1) {
//        const sub_field = @field(FieldT, sub_field_names[0]);
//        const SubFieldT = @TypeOf(sub_field);
//        const cond_kw: InteractExprKeywords.Condition, 
//        const cond_val: SubFieldT =
//            condition: {
//                var tokens = mem.split(u8, expr, ' ');
//                const val_str = tokens.next();
//                break :condition .{
//                    meta.stringToEnum(InteractExprKeywords.Condition, tokens.first()) orelse return error.UnknownConditionKeyword,
//                    switch (@typeInfo(SubFieldT)) {
//                        .Struct, .Union => try SubFieldT.fromStr(val_str),
//                        .Int => try fmt.parseInt(SubFieldT, val_str, 0),
//                        .Bool => ascii.eqlIgnoreCase(val_str, "true"),
//                        .Pointer => |ptr| slice: {
//                            if (ptr.child != u8) return error.PointerMustBeStringSlice;
//                            break :slice val_str;
//                        },
//                        inline else => error.UnsupportedType,
//                    }
//                };
//            };
//        _ = cond_val;
//        switch (cond_kw) {
//            .EQUALS => {},
//            else => {},
//        }
//        switch (@typeInfo(SubFieldT)) {
//            else => {},
//        }
//    }
//
//    switch (@typeInfo(FieldT)) {
//        .Struct, .Union => |type_info| {
//            inline for (type_info.fields) |sub_f| {
//                if (!mem.eql(u8, sub_field_names[0], sub_f)) continue;
//                return parseIfExpr(@field(FieldT, sub_f.name), sub_field_names[1..], expr);
//            }
//            else return error.UnknownField;
//        },
//        inline else => return error.ReachedDeepestField,
//    }
//}
//
//fn setDGField(dg: Datagrams.Full, expr: []const []const u8) !void {
//    _ = dg;
//    _ = expr;
//}
