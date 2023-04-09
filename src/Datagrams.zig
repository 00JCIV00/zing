//! Datagram Union Templates

const std = @import("std");
const meta = std.meta;

const eql = std.mem.eql;
const strToEnum = std.meta.stringToEnum;


const lib = @import("lib.zig");
const BFG = lib.BitFieldGroup;
const Frames = lib.Frames;
const Packets = lib.Packets;

/// Layer 2
pub const Layer2Header = union(enum) {
    eth: Frames.EthFrame.Header,
    wifi: Frames.WifiFrame.Header,
};

/// Layer 2 Footers
pub const Layer2Footer = union(enum) {
    eth: Frames.EthFrame.Footer,
    wifi: Frames.WifiFrame.Footer,
};

/// Layer 3 Headers
pub const Layer3 = union(enum) {
    ip: Packets.IPPacket.Header,
    icmp: Packets.ICMPPacket,
};

/// Layer 4 Headers
pub const Layer4 = union(enum) {
    udp: Packets.UDPPacket.Header,
    tcp: Packets.TCPPacket.Header,
};

/// Full Layer 2 - 4 Datagram
pub const Full = struct {
    l2_header: Layer2Header = .{ .eth = .{} },
    l3_header: Layer3 = .{ .ip = .{} },
    l4_header: ?Layer4 = .{ .udp = .{} },
    data: []const u8 = "Hello World!",
    l2_footer: Layer2Footer = .{ .eth = .{} },

    pub fn init(layer: u3, headers: [][]const u8, data: []const u8, footer: []const u8) !@This() {
        const l_diff = 2 - @intCast(i4, layer); // Layer Difference. Aligns input headers based on given layer.
        return .{
            .l2_header = if (layer > 2) .{ .eth = .{} } else l2Hdr: {
                const l2_hdr_type = strToEnum(meta.Tag(Layer2Header), headers[0]) orelse return error.InvalidHeader;
                switch(l2_hdr_type) { 
                    inline else => |l2_hdr_tag| break :l2Hdr @unionInit(Layer2Header, @tagName(l2_hdr_tag), .{}),
                }
            },
            .l3_header = if (layer > 3) .{ .ip = .{} } else l3Hdr: {
                const l3_hdr_type = strToEnum(meta.Tag(Layer3), headers[@intCast(u3, l_diff + 1)]) orelse return error.InvalidHeader;
                switch(l3_hdr_type) {
                    inline else => |l3_hdr_tag| break :l3Hdr @unionInit(Layer3, @tagName(l3_hdr_tag), .{}),
                }
            },
            .l4_header = l4Hdr: {
                const l4_hdr_type = strToEnum(meta.Tag(Layer4), headers[@intCast(u3, l_diff + 2)]) orelse break :l4Hdr null;
                switch (l4_hdr_type) {
                    inline else => |l4_hdr_tag| break :l4Hdr @unionInit(Layer4, @tagName(l4_hdr_tag), .{}),
                }
            },
            .data = data,
            .l2_footer = if (layer > 2) .{ .eth = .{} } else l2Hdr: {
                const l2_ftr_type = strToEnum(meta.Tag(Layer2Footer), footer) orelse return error.InvalidFooter;
                switch(l2_ftr_type) { 
                    inline else => |l2_ftr_tag| break :l2Hdr @unionInit(Layer2Footer, @tagName(l2_ftr_tag), .{}),
                }
            },
        };
    }
};

