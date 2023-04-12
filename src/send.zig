//! Send Datagrams 

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const fs = std.fs;
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

pub fn sendDatagramFile(alloc: Allocator, filename: []const u8, if_idx: i32) !void {
    var datagram: Datagrams.Full = try craft.decodeDatagram(alloc, filename);

    var data_list = std.ArrayList(u8).init(alloc);
    defer data_list.deinit();
    inline for (meta.fields(@TypeOf(datagram))) |field| {
        const f_self = @field(datagram, field.name);
        const field_info = @typeInfo(field.type);
        switch (field_info) {
            .Optional, .Union => bfgNull: {
                const bfg = if (field_info != .Optional) f_self
                            else if (f_self != null) f_self.?
                            else break :bfgNull;
                switch(meta.activeTag(bfg)) {
                    inline else => |tag| {
                        var bfg_data = @field(bfg, @tagName(tag));
                        const bfg_type = @TypeOf(bfg_data);
                        const net_bytes = try bfg_data.asNetBytes(alloc);
                        try data_list.appendSlice(net_bytes);
                        std.debug.print(\\New BitFieldGroup:
                                        \\- Name: {s}
                                        \\- Size: {d}B
                                        \\- Bytes: {any}
                                        \\- BFG: 
                                        \\
                                        , .{ @typeName(bfg_type), @sizeOf(bfg_type), net_bytes });
                        _ = try bfg_data.formatToText(stdout, .{
                            .add_bit_ruler = true,
                            .add_bitfield_title = true
                        });
                    }
                }
            },
            .Pointer => try data_list.appendSlice(f_self),
            else => |odd| {
                std.debug.print(\\No handling for: 
                                \\- Type: '{s}'
                                \\- Obj: {}
                                \\
                                , .{ @typeName(@TypeOf(odd)), odd });
                return;
            },
        }
        std.debug.print("(Updated Data: {d})\n", .{ data_list.items.len });
    }
    var data_buf = try data_list.toOwnedSlice();
    //mem.byteSwapAllFields(@TypeOf(data_buf), &data_buf);

    // Linux Interface Constants. Found in .../linux/if_ether.h and if_arp.h
    const ETH_P_ALL = mem.nativeToBig(u16, 0x03);
    const ARPHRD_ETHER = mem.nativeToBig(u16, 1);
    const PACKET_BROADCAST = mem.nativeToBig(u8, 1);

    var send_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, ETH_P_ALL); 
    var addr = mem.nativeToBig(u48, 0xFFFFFFFFFFFF);
    var addr_ary = @constCast(mem.asBytes(&addr)).*;
    var if_addr = linux.sockaddr.ll { 
        .family = linux.AF.PACKET, 
        .protocol = ETH_P_ALL,
        .ifindex = if_idx,
        .pkttype = PACKET_BROADCAST,
        .hatype = ARPHRD_ETHER, 
        .halen = 6,
        .addr = addr_ary,
    }; 
    _ = if_addr;

    std.debug.print("Writing {d}B...\n", .{ data_buf.len });
    //const written_bytes = linux.sendto(send_sock, data_buf, 0, &if_addr, @sizeOf(@TypeOf(if_addr))) catch |err| {
    const written_bytes = os.send(send_sock, data_buf, 0) catch |err| {
        std.debug.print("There was an issue writing the data:\n{}\n", .{ err });
        return;
    };
    std.debug.print("Successfully wrote {d}B / {d}B!", .{ written_bytes, data_buf.len }); 
}
