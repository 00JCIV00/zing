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
    const l2_tag = meta.activeTag(datagram.l2_header);
    switch(l2_tag) {
        inline else => |tag| {
            var tag_self = @field(datagram.l2_header, @tagName(tag));
            var dst_mac = tag_self.dst_mac_addr;
            var src_mac = tag_self.src_mac_addr;
            var src_addr_buf = try mem.concat(alloc, u8, &.{ try src_mac.asBytes(alloc), &.{ 0x00, 0x00 } } );
            std.debug.print("DST MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try dst_mac.asBytes(alloc)) });
            std.debug.print("SRC MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try src_mac.asBytes(alloc)) });
            for (src_addr[0..], src_addr_buf) |*src, buf| src.* = buf;
        }
    }

    var ifr = mem.zeroes(os.ifreq);
    var if_name_ary: [16]u8 = .{0} ** 16;
    mem.copy(u8, if_name_ary[0..], if_name);
    ifr.ifrn.name = if_name_ary;
    try os.ioctl_SIOCGIFINDEX(send_sock, &ifr);

    var if_addr = linux.sockaddr.ll { 
        .family = linux.AF.PACKET, 
        .protocol = ETH_P_ALL,
        .hatype = ARPHRD_ETHER, 
        .ifindex = ifr.ifru.ivalue,
        .pkttype = mem.nativeToBig(u8, 3),
        .halen = 6,
        .addr = src_addr,
    }; 

    // Write to Socket
    std.debug.print("Writing {d}B to '{s} | {d} | {s}'...\n", .{ data_buf.len, if_name, ifr.ifru.ivalue, fmt.fmtSliceHexUpper(src_addr[0..6]) });
    //const written_bytes = os.send(send_sock, data_buf, 0) catch |err| {
    //const written_bytes = os.sendto(send_sock, data_buf[0..data_buf.len - 4], 0, @ptrCast(*linux.sockaddr, &if_addr), @sizeOf(@TypeOf(if_addr))) catch |err| {
    const written_bytes = os.sendto(send_sock, data_buf, 0, @ptrCast(*linux.sockaddr, &if_addr), @sizeOf(@TypeOf(if_addr))) catch |err| {
        std.debug.print("There was an issue writing the data:\n{}\n", .{ err });
        return;
    };
    std.debug.print("Successfully wrote {d}B / {d}B!\n", .{ written_bytes, data_buf.len }); 
}
