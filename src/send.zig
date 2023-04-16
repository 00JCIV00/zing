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
    _ = try datagram.formatToText(stdout, .{
        .add_bit_ruler = true,
        .add_bitfield_title = true
    });
    var data_buf = try datagram.asNetBytes(alloc);
    //var data_list = std.ArrayList(u8).init(alloc);
    //defer data_list.deinit();
    //inline for (meta.fields(@TypeOf(datagram))) |field| {
    //    const field_self = @field(datagram, field.name);
    //    const field_info = @typeInfo(field.type);
    //    switch (field_info) {
    //        .Optional, .Union => bfgNull: {
    //            const bfg = if (field_info != .Optional) field_self
    //                        else if (field_self != null) field_self.?
    //                        else {
    //                            std.debug.print("NULL LAYER 4 HEADER!\n", .{});
    //                            break :bfgNull;
    //                        };
    //            switch(meta.activeTag(bfg)) {
    //                inline else => |tag| {
    //                    var bfg_data = @field(bfg, @tagName(tag));
    //                    const bfg_type = @TypeOf(bfg_data);
    //                    //const net_bytes = try bfg_data.asNetBytes(alloc);
    //                    const bfg_bytes = bfg_data.asBytes();//mem.asBytes(&bfg_data)[0..(@bitSizeOf(bfg_type) / 8)];
    //                    try data_list.appendSlice(&bfg_bytes);
    //                    std.debug.print(\\New BitFieldGroup:
    //                                    \\- Name: {s}
    //                                    \\- Size: {d}B
    //                                    \\- Bytes: {any}
    //                                    \\- BFG: 
    //                                    \\
    //                                    , .{ @typeName(bfg_type), @sizeOf(bfg_type), bfg_bytes });
    //                    _ = try bfg_data.formatToText(stdout, .{
    //                        .add_bit_ruler = true,
    //                        .add_bitfield_title = true
    //                    });
    //                }
    //            }
    //        },
    //        .Pointer => try data_list.appendSlice(field_self),
    //        else => |odd| {
    //            std.debug.print(\\No handling for: 
    //                            \\- Type: '{s}'
    //                            \\- Obj: {}
    //                            \\
    //                            , .{ @typeName(@TypeOf(odd)), odd });
    //            return;
    //        },
    //    }
    //    std.debug.print("(Updated Data: {d}B)\n", .{ data_list.items.len });
    //}

    //// Convert Data Bytes to Net Bytes (32-bit words in Big Endian).
    //var data_buf = try data_list.toOwnedSlice();
    //std.debug.print("TOTAL BYTES: {d}B\n", .{ data_buf.len });
    //const pad_needed = data_buf.len % 32;
    //var data_pad_buf = if (pad_needed == 0) data_buf else padBuf: {
    //    var padding: [32]u8 = undefined;
    //    for (padding[0..]) |*byte| byte.* = 0;
    //    break :padBuf try fmt.allocPrint(alloc, "{s}{s}", .{ data_buf, padding[0..pad_needed] });
    //};
    //std.debug.print(\\TOTAL PADDED BYTES: {d}B
    //                \\BYTES TO WRITE:
    //                \\{s}
    //                \\
    //                , .{ data_pad_buf.len, fmt.fmtSliceHexUpper(data_pad_buf) });
    //var word_buf = mem.bytesAsSlice(u32, data_pad_buf);
    //var net_buf = std.ArrayList(u8).init(alloc);
    //defer net_buf.deinit();
    //for (word_buf) |word| try net_buf.appendSlice(mem.asBytes(&mem.nativeToBig(u32, word)));
    //var data_slice = try net_buf.toOwnedSlice();

    // Linux Interface Constants. Found in .../linux/if_ether.h, if_arp.h, if_socket.h, etc
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);
    //const ARPHRD_ETHER = mem.nativeToBig(u16, 1);
    //const PACKET_BROADCAST = mem.nativeToBig(u8, 1);
    //const SO_BINDTODEVICE = mem.nativeToBig(u32, 25);

    // Setup Socket
    var send_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL);
    var sock_if_opt = if_name;
    try os.setsockopt(send_sock, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, sock_if_opt[0..] );

    //var addr = mem.nativeToBig(u48, 0xFFFFFFFFFFFF);
    //var addr_ary = @constCast(mem.asBytes(&addr)).*;
    //var if_addr = linux.sockaddr.ll { 
    //    .family = linux.AF.PACKET, 
    //    .protocol = ETH_P_ALL,
    //    .ifindex = if_name,
    //    .pkttype = PACKET_BROADCAST,
    //    .hatype = ARPHRD_ETHER, 
    //    .halen = 6,
    //    .addr = addr_ary,
    //}; 
    //_ = if_addr;

    // Write to Socket
    std.debug.print("Writing {d}B...\n", .{ data_buf.len });
    //const written_bytes = linux.sendto(send_sock, data_buf, 0, &if_addr, @sizeOf(@TypeOf(if_addr))) catch |err| {
    const written_bytes = os.send(send_sock, data_buf, 0) catch |err| {
        std.debug.print("There was an issue writing the data:\n{}\n", .{ err });
        return;
    };
    std.debug.print("Successfully wrote {d}B / {d}B!", .{ written_bytes, data_buf.len }); 
}
