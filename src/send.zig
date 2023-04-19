//! Send Datagrams 

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const fs = std.fs;
const fmt = std.fmt;
const linux = os.linux;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;

const Allocator = mem.Allocator;
const eql = mem.eql;
const socket = os.socket;
const strToEnum = std.meta.stringToEnum;

const lib = @import("lib.zig");
const Addresses = lib.Addresses;
const craft = lib.craft;
const Datagrams = lib.Datagrams;

pub fn sendDatagramFile(alloc: Allocator, filename: []const u8, if_name: []u8) !void {
    // Gather Data Bytes
    var datagram: Datagrams.Full = try craft.decodeDatagram(alloc, filename);
    try datagram.calcFromPayload(alloc);
    var data_buf = try datagram.asNetBytes(alloc);
    _ = try datagram.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true
    });
    std.debug.print(\\Net Bytes:
                    \\- Len: {d}
                    \\{s}
                    \\
                    , .{ data_buf.len, fmt.fmtSliceHexUpper(data_buf) });

    // Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);
    const ARPHRD_ETHER = mem.nativeToBig(u16, 1);
    //const PACKET_BROADCAST = mem.nativeToBig(u8, 1);

    // Setup Socket
    var send_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL);
    defer os.closeSocket(send_sock);
    var sock_if_opt = if_name;
    try os.setsockopt(send_sock, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, sock_if_opt[0..]);
    var src_addr: [8]u8 = undefined; 
    std.debug.print("L2 HEADER BYTES:\n{s}\n", .{ fmt.fmtSliceHexUpper(try datagram.l2_header.asBytes(alloc)) });
    switch(meta.activeTag(datagram.l2_header)) {
        inline else => |tag| {
            var src_addr_buf = try mem.concat(alloc, u8, &.{ mem.asBytes(&@field(datagram.l2_header, @tagName(tag)).src_mac_addr)[0..6], &.{ 0x00, 0x00 } } );
            for (src_addr[0..], src_addr_buf) |*src, buf| src.* = buf;
        }
    }

    var if_addr = linux.sockaddr.ll { 
        .family = linux.AF.PACKET, 
        .protocol = ETH_P_ALL,
        .hatype = ARPHRD_ETHER, 
        .ifindex = 2,
        .pkttype = mem.nativeToBig(u8, 3),
        .halen = 6,
        .addr = src_addr,
    }; 

    // Write to Socket
    std.debug.print("Writing {d}B...\n", .{ data_buf.len });
    //const written_bytes = os.send(send_sock, data_buf, 0) catch |err| {
    const written_bytes = os.sendto(send_sock, data_buf, 0, @ptrCast(*linux.sockaddr, &if_addr), @sizeOf(@TypeOf(if_addr))) catch |err| {
        std.debug.print("There was an issue writing the data:\n{}\n", .{ err });
        return;
    };
    std.debug.print("Successfully wrote {d}B / {d}B!\n", .{ written_bytes, data_buf.len }); 
}
