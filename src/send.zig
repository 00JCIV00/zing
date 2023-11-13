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
const consts = lib.constants;
const conn = lib.connect;
const Addresses = lib.Addresses;
const craft = lib.craft;
const Datagrams = lib.Datagrams;

/// Send a Custom Datagram from the given File (filename) to the given Interface (if_name).
pub fn sendDatagramFile(alloc: mem.Allocator, filename: []const u8, if_name: []const u8) !void {
    var datagram: Datagrams.Full = try craft.decodeDatagram(alloc, filename);
    try sendDatagramInterface(alloc, datagram, if_name);
}

/// Config for `sendDatagramFileCmd`().
pub const SendDatagramFileConfig = struct{
    filename: []const u8,
    if_name: ?[]const u8 = "eth0",
};

/// Cova CLI Wrapper for `sendDatagramFile`().
pub fn sendDatagramFileCmd(alloc: mem.Allocator, config: SendDatagramFileConfig) !void {
    try sendDatagramFile(alloc, config.filename, config.if_name.?);
}

/// Send the provided Layer 2 Datagram (`datagram_full`) on the provided Network Interface (`if_name`).
pub fn sendDatagramInterface(alloc: mem.Allocator, datagram_full: Datagrams.Full, if_name: []const u8) !void {
    var send_sock = try conn.IFSocket.init(.{ .if_name = if_name });
    return sendDatagram(alloc, datagram_full, send_sock);
}
/// Send the provided Layer 2 Datagram (`datagram_full`) on the provided Network Interface (`if_name`).
pub fn sendDatagram(alloc: mem.Allocator, datagram_full: Datagrams.Full, send_sock: conn.IFSocket) !void {
    // Gather Data Bytes
    var datagram = @constCast(&datagram_full);
    try datagram.calcFromPayload(alloc);
    var payload_bytes = try datagram.asNetBytes(alloc);
    //_ = try datagram.formatToText(stdout, .{
    //    .add_bit_ruler = true,
    //    .add_bitfield_title = true
    //});
    
    // Source MAC Address
    //var src_addr: [8]u8 = undefined; 
    //const l2_tag = meta.activeTag(datagram.l2_header);
    //switch(l2_tag) {
    //    inline else => |tag| {
    //        var tag_self = @field(datagram.l2_header, @tagName(tag));
    //        var dst_mac = tag_self.dst_mac_addr;
    //        var src_mac = tag_self.src_mac_addr;
    //        var src_addr_buf = try mem.concat(alloc, u8, &.{ try src_mac.asBytes(alloc), &.{ 0x00, 0x00 } } );
    //        log.debug("DST MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try dst_mac.asBytes(alloc)) });
    //        log.debug("SRC MAC: {s}\n", .{ fmt.fmtSliceHexUpper(try src_mac.asBytes(alloc)) });
    //        for (src_addr[0..], src_addr_buf) |*src, buf| src.* = buf;
    //    }
    //}

    try sendBytes(alloc, payload_bytes, send_sock);
}

/// Send the provided Payload Bytes (`payload_bytes`) from the provided Source MAC Address (`src_addr`) to the provided Network Interface (`if_name`).
pub fn sendBytes(alloc: mem.Allocator, payload_bytes: []u8, send_sock: conn.IFSocket) !void {
    _ = alloc;

    // Write to Socket
    log.debug("Writing {d}B to '{s} | {s}'...", .{ payload_bytes.len, send_sock.if_name, fmt.fmtSliceHexUpper(&@as([6]u8, @bitCast((try send_sock.getMAC())))) });
    const written_bytes = os.write(send_sock.desc, payload_bytes) catch return error.CouldNotWriteData;
    //const written_bytes = os.sendto(send_sock, payload_bytes, 0, @ptrCast(*linux.sockaddr, &if_addr), @sizeOf(@TypeOf(if_addr))) catch return error.CouldNotWriteData;
    log.debug("Successfully wrote {d}B / {d}B!", .{ written_bytes, payload_bytes.len }); 

}
