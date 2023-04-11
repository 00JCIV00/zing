//! Send Datagrams 

const std = @import("std");
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

pub fn sendDatagramFile(alloc: Allocator, filename: []const u8, in_addr: Addresses.MAC) !void {
    var datagram: Datagrams.Full = try craft.decodeDatagram(alloc, filename);

    var data_list = std.ArrayList(u8).init(alloc);
    defer data_list.deinit();
    inline for (meta.fields(@TypeOf(datagram))) |field| {
        const f_self = @field(datagram, field.name);
        const field_info = @typeInfo(field.type);
        switch (field_info) {
            .Optional, .Union => bfgData: {
                const bfg = if (field_info != .Optional) f_self
                            else if (f_self != null) f_self.?
                            else break :bfgData;
                switch(meta.activeTag(bfg)) {
                    inline else => |tag| try data_list.appendSlice(mem.asBytes(&@field(bfg, @tagName(tag))))
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
        std.debug.print("- Updated Data: {d}\n", .{ data_list.items.len });
    }
    var data_buf = "HELLO WORLD";//try data_list.toOwnedSlice();


    var send_sock = try socket(linux.AF.PACKET, linux.SOCK.RAW, mem.nativeToBig(u8, 0x03)); // <- 0x03 is the constant for ETH_P_ALL
    _ = in_addr;
    //const if_addr = @ptrCast(*os.sockaddr, @constCast(&addr));
    //var addr = mem.nativeToBig(u48, @bitCast(u48, in_addr));
    //var addr_ary = @constCast(mem.asBytes(&addr)).*;
    //var sockaddr_buf: [14]u8 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    //for (addr_ary, sockaddr_buf[0..addr_ary.len]) |byte, *s_byte| s_byte.* = byte;
    //const if_addr = linux.sockaddr { .family = 17, .data = sockaddr_buf }; // 17 is the constant value for AF_PACKET

    std.debug.print("Writing {d}B...\n", .{ data_buf.len });
    const written_bytes = os.send(send_sock, data_buf, 0) catch |err| {
        std.debug.print("There was an issue writing the data:\n{}\n", .{ err });
        return;
    };
    std.debug.print("Successfully wrote {d}B / {d}B!", .{ written_bytes, data_buf.len }); 
}
