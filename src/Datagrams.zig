//! Datagram Union Templates

const std = @import("zig");

const lib = @import("lib.zig");
const BFG = lib.BitFieldGroup;
const Frames = lib.Frames;
const Packets = lib.Packets;

/// Layer 2
pub const Layer2Header = union(enum) {
    eth: Frames.EthFrame.Header,
};

/// Layer 2 Footers
pub const Layer2Footer = union(enum) {
    eth: Frames.EthFrame.Footer,
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
};

