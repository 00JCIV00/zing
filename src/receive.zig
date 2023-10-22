//! Receive Datagrams

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const fs = std.fs;
const fmt = std.fmt;
const linux = os.linux;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;

const eql = mem.eql;
const socket = os.socket;
const sleep = std.time.sleep;
const strToEnum = std.meta.stringToEnum;

const lib = @import("zinglib.zig");
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

/// Config for recvDatagramCmd
pub const RecvDatagramConfig = struct{
    /// Interface Name
    if_name: []const u8 = "eth0",
};

/// Cova CLI Wrapper for `recvDatagramFile`().
pub fn recvDatagramCmd(alloc: mem.Allocator, writer: anytype, config: RecvDatagramConfig) !void {
    return recvDatagram(alloc, writer, config.if_name);
}

/// Receive a Layer 2 Datagram from the specified interface `(if_name)`.
/// (WIP) Parameters on contents chaning rapidly.
pub fn recvDatagram(alloc: mem.Allocator, writer: anytype, if_name: []const u8) !void {
    //_ = alloc;

    // Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);

    // Setup Socket
    var recv_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL);
    defer os.closeSocket(recv_sock);
    var if_name_ary: [16]u8 = .{0} ** 16;
    mem.copy(u8, if_name_ary[0..], if_name);


    // Receive from Socket
    log.info("Receiving a Datagram from '{s}'...", .{ if_name });
    var recv_buf: [1518]u8 = .{ 0 } ** 1518;
    const recv_bytes = try os.recv(recv_sock, recv_buf[0..], 0);
    log.info("Received {d} bytes.", .{ recv_bytes });

    var eth_hdr: lib.Frames.EthFrame.Header = @bitCast(recv_buf[0..@bitSizeOf(lib.Frames.EthFrame.Header) / 8].*);
    //var eth_hdr: *lib.Frames.EthFrame.Header = @alignCast(@ptrCast(recv_buf[0..@sizeOf(lib.Frames.EthFrame.Header)]));
    const src_mac = eth_hdr.src_mac_addr;
    const dst_mac = eth_hdr.dst_mac_addr;
    
    _ = try eth_hdr.formatToText(writer, .{});
    log.info(
        \\
        \\SRC MAC: {s}
        \\DST MAC: {s}
        \\
        \\
        , .{
            try src_mac.toStr(alloc),
            try dst_mac.toStr(alloc),
        }
    );
}
