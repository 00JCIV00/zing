//! Receive Datagrams

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
const consts = lib.constants;
const conn = lib.connect;
const ia = lib.interact;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;


/// Config for `recvDatagramCmd` and `recvDatagramStreamCmd`
pub const RecvDatagramConfig = struct{
    /// Interface Name.
    if_name: []const u8 = "eth0",
    /// Max Datagrams. (Stream Only)
    max_dg: ?u64 = null, 
};

/// Cova CLI Wrapper for `recvDatagram`().
pub fn recvDatagramCmd(alloc: mem.Allocator, config: RecvDatagramConfig) !Datagrams.Full {
    return recvDatagramInterface(alloc, config.if_name);
}

/// Receive a Layer 2 Datagram from the specified interface `(if_name)`.
pub fn recvDatagramInterface(alloc: mem.Allocator, if_name: []const u8) !Datagrams.Full {
    const recv_sock = try conn.IFSocket.init(.{ .if_name = if_name });
    defer recv_sock.close();
    return recvDatagram(alloc, recv_sock);
}

/// Receive a Layer 2 Datagram from the specified Socket `(recv_sock)`.
pub fn recvDatagram(alloc: mem.Allocator, recv_sock: conn.IFSocket) !Datagrams.Full {

    // Receive from Socket
    log.debug("Awaiting a Datagram from '{s}'...", .{ recv_sock.if_name });
    const max_frame_len: usize, const l2_type: meta.Tag(Datagrams.Layer2Header) = switch (recv_sock.hw_fam) {
        consts.ARPHRD_ETHER => .{ 1518, .eth },
        consts.ARPHRD_IEEE80211 => {
            log.debug("WiFi Interface Detected.", .{});
            log.debug("WiFi is not yet implemented. Stopping.", .{});
            return error.UnimplementedReceiveType;
            // return .{ 2304, .wifi };
        },
        else => |if_fam| {
            log.err("Unrecognized Interface Family '{d}' for '{s}'.", .{ if_fam, recv_sock.if_name });
            return error.UnrecognizedInterfaceType;
        },
    };
    const recv_buf = try alloc.alloc(u8, max_frame_len);
    const recv_bytes = try os.recv(recv_sock.desc, recv_buf[0..], 0);
    if (recv_bytes > max_frame_len) {
        log.warn("The number of received bytes '{d}B' is greater than the expected frame length '{d}B' for this interface '{s}'.", .{ 
            recv_bytes, 
            max_frame_len,
            recv_sock.if_name,
        });
        return error.UnexpectedlyLargeFrame;
    }
    const frame_buf = recv_buf[0..recv_bytes];
    log.debug("Received a {d}B Datagram.", .{ recv_bytes });

    return Datagrams.Full.fromBytes(alloc, frame_buf, l2_type);
}


/// Cova CLI Wrapper for `recvDatagramStream`().
pub fn recvDatagramStreamCmd(alloc: mem.Allocator, writer: anytype, dg_buf: *std.ArrayList(Datagrams.Full), config: RecvDatagramConfig) !void {
    return recvDatagramStream(alloc, writer, config.if_name, dg_buf, config.max_dg);
}

/// Receive a Stream of Datagrams to an ArrayList.
pub fn recvDatagramStream(alloc: mem.Allocator, writer: anytype, if_name: []const u8, dg_buf: *std.ArrayList(Datagrams.Full), max_dg: ?u64) !void {
    const recv_sock = try conn.IFSocket.init(.{ .if_name = if_name });
    defer recv_sock.close();
    var count: u64 = 1;
    log.debug("Receiving Datagram Stream...\n", .{});
    defer log.debug("Received {d} Datagrams.", .{ count - 1 });
    while (if (max_dg) |max| count <= max else true) {
        const datagram = recvDatagram(alloc, recv_sock) catch |err| switch (err) {
            error.UnimplementedType => continue,
            else => return err,
        };
        try dg_buf.append(datagram);        

        try writer.print(
            \\
            \\Datagram Received:
            \\{d:0>20}
            \\{s}
            \\
            \\==============================
            \\
            \\
            , .{ 
                count,
                datagram 
            }
        );
        count += 1;
    }
}


/// Receive a Stream of Datagrams to an Interaction Buffer.
/// This is designed to be run in its own Thread.
pub fn recvDatagramThread(alloc: mem.Allocator, recv_sock: conn.IFSocket, dg_buf: *ia.InteractBuffer, max_dg: u32) !void {
    var dg_count: u32 = 0;
    while (if (max_dg > 0) dg_count <= max_dg else true) : (dg_count += 1) {
        const datagram = recvDatagram(alloc, recv_sock) catch |err| switch (err) {
            error.UnimplementedType => continue,
            else => return err,
        };
        try dg_buf.push(datagram);
    }
}
