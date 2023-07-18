//! Send Datagrams 

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
const craft = lib.craft;
const Datagrams = lib.Datagrams;

/// Send a Custom Datagram from the given File (filename) to the given Interface (if_name).
pub fn sendDatagramFile(alloc: mem.Allocator, filename: []const u8, if_name: []const u8) !void {
    var datagram: Datagrams.Full = try craft.decodeDatagram(alloc, filename);
    try sendDatagram(alloc, datagram, if_name);
}

/// Config for `sendDatagramFileCmd()`.
pub const SendDatagramFileConfig = struct{
    filename: []const u8,
    if_name: ?[]const u8 = "eth0",
};

/// Cova CLI Wrapper for `sendDatagramFile()`.
pub fn sendDatagramFileCmd(alloc: mem.Allocator, config: SendDatagramFileConfig) !void {
    try sendDatagramFile(alloc, config.filename, config.if_name.?);
}

pub fn sendDatagram(alloc: mem.Allocator, datagram_full: Datagrams.Full, if_name: []const u8) !void {
    // Gather Data Bytes
    var datagram = @constCast(&datagram_full);
    try datagram.calcFromPayload(alloc);
    var payload_bytes = try datagram.asNetBytes(alloc);
    _ = try datagram.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true
    });
    
    // Source MAC Address
    var src_addr: [8]u8 = undefined; 
    const l2_tag = meta.activeTag(datagram.l2_header);
    switch(l2_tag) {
        inline else => |tag| {
            var tag_self = @field(datagram.l2_header, @tagName(tag));
            var dst_mac = tag_self.dst_mac_addr;
            var src_mac = tag_self.src_mac_addr;
            var src_addr_buf = try mem.concat(alloc, u8, &.{ try src_mac.asBytes(alloc), &.{ 0x00, 0x00 } } );
            log.debug("DST MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try dst_mac.asBytes(alloc)) });
            log.debug("SRC MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try src_mac.asBytes(alloc)) });
            for (src_addr[0..], src_addr_buf) |*src, buf| src.* = buf;
        }
    }

    try sendBytes(alloc, payload_bytes, src_addr, if_name);
}

pub fn sendBytes(alloc: mem.Allocator, payload_bytes: []u8, src_addr: [8]u8, if_name: []const u8) !void {
    _ = alloc;

    // Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);
    const ARPHRD_ETHER = mem.nativeToBig(u16, 1);
    //const PACKET_BROADCAST = mem.nativeToBig(u8, 1);
    //const IFF_ALLMULTI: i16 = 0x200;//mem.nativeToBig(i16, 0x200);
    //const SIOCSIFFLAGS: u32 = 0x8914;//mem.nativeToBig(u32, 0x8914);

    // Setup Socket
    var send_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL);
    defer os.closeSocket(send_sock);
    //os.setsockopt(send_sock, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, if_name) catch return error.CouldNotConnectToInterface;
    var if_name_ary: [16]u8 = .{0} ** 16;
    mem.copy(u8, if_name_ary[0..], if_name);

    // - Interface Index
    var ifr_idx = mem.zeroes(os.ifreq);
    ifr_idx.ifrn.name = if_name_ary;
    try os.ioctl_SIOCGIFINDEX(send_sock, &ifr_idx);

    // - Interface Socket Address
    var if_addr = linux.sockaddr.ll { 
        .family = linux.AF.PACKET, 
        .protocol = ETH_P_ALL,
        .hatype = ARPHRD_ETHER, 
        .ifindex = ifr_idx.ifru.ivalue,
        .pkttype = 3,// <- 1 = BROADCAST, 3 = OTHERHOST
        .halen = 6,
        .addr = src_addr,
    }; 

    // - Bind to Socket
    os.bind(send_sock, @as(*linux.sockaddr, @ptrCast(&if_addr)), @sizeOf(@TypeOf(if_addr))) catch return error.CouldNotConnectToInterface;

    // - Set Promiscuous Mode - (Does not have intended effect) 
    //var ifr_flags = mem.zeroes(os.ifreq);
    //ifr_flags.ifrn.name = if_name_ary;
    //ifr_flags.ifru.flags |= IFF_ALLMULTI;
    //const set_prom = linux.ioctl(send_sock, SIOCSIFFLAGS, @ptrToInt(&ifr_flags));
    //if (set_prom != 0) {
    //    std.debug.print("There was an issue opening the socket in Promiscuous Mode:\n{d}\n", .{ os.errno(set_prom) });
    //    //return error.CouldNotOpenPromiscuous;
    //}
    //else std.debug.print("Opened Promiscuous Mode!\n", .{});
    //defer {
    //    ifr_flags.ifru.flags &= ~IFF_ALLMULTI;
    //    _ = linux.ioctl(send_sock, SIOCSIFFLAGS, @ptrToInt(&ifr_flags));
    //}

    // Write to Socket
    log.info("Writing {d}B to '{s} | {d} | {s}'...", .{ payload_bytes.len, if_name, ifr_idx.ifru.ivalue, fmt.fmtSliceHexUpper(src_addr[0..6]) });
    const written_bytes = os.write(send_sock, payload_bytes) catch return error.CouldNotWriteData;
    //const written_bytes = os.sendto(send_sock, payload_bytes, 0, @ptrCast(*linux.sockaddr, &if_addr), @sizeOf(@TypeOf(if_addr))) catch return error.CouldNotWriteData;
    log.info("Successfully wrote {d}B / {d}B!", .{ written_bytes, payload_bytes.len }); 

}
