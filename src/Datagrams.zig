//! Datagram Union Templates

// Standard
const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const meta = std.meta;

const eql = mem.eql;
const strToEnum = meta.stringToEnum;

// Zing
const lib = @import("zinglib.zig");
const BFG = lib.BitFieldGroup;
const Frames = lib.Frames;
const Packets = lib.Packets;


/// Layer 2
pub const Layer2Header = union(enum) {
    eth: Frames.EthFrame.Header,
    wifi: Frames.WifiFrame.Header,

    pub usingnamespace implCommonToAll(@This());
};

/// Layer 2 Footers
pub const Layer2Footer = union(enum) {
    eth: Frames.EthFrame.Footer,
    wifi: Frames.WifiFrame.Footer,

    pub usingnamespace implCommonToAll(@This());
};

/// Layer 3 Headers
pub const Layer3 = union(enum) {
    ip: Packets.IPPacket.Header,
    icmp: Packets.ICMPPacket,

    pub usingnamespace implCommonToAll(@This());
};

/// Layer 4 Headers
pub const Layer4 = union(enum) {
    udp: Packets.UDPPacket.Header,
    tcp: Packets.TCPPacket.Header,

    pub usingnamespace implCommonToAll(@This());
};

/// Common-to-All Functions
fn implCommonToAll(comptime T: type) type {
    return struct {
        /// Call the asBytes method of the inner BitFieldGroup.
        pub fn asBytes(self: *T, alloc: mem.Allocator) ![]u8 {
            return switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @field(self, @tagName(tag));
                    return if (@hasDecl(@TypeOf(bfg), "asBytes")) try bfg.asBytes(alloc)
                           else error.NoAsBytesMethod;
                },
            };
        }

        /// Call the asNetBytesBFG method of the inner BitFieldGroup.
        pub fn asNetBytes(self: *T, alloc: mem.Allocator) ![]u8 {
            return switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @field(self, @tagName(tag));
                    return if (@hasDecl(@TypeOf(bfg), "asBytes")) try bfg.asNetBytesBFG(alloc)
                           else error.NoAsBytesMethod;
                },
            };
        }


        /// Call the specific calc method of the inner BitFieldGroup.
        pub fn calc(self: *T, alloc: mem.Allocator, payload: []u8) !void {
            switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @constCast(&@field(self, @tagName(tag)));
                    if (@hasDecl(@TypeOf(bfg.*), "calcLengthAndChecksum")) try bfg.calcLengthAndChecksum(alloc, payload)
                    else if (@hasDecl(@TypeOf(bfg.*), "calcCRC")) try bfg.calcCRC(alloc, payload)
                    else return error.NoCalcMethod;
                },
            }
            return;
        }
    };
}

/// Full Layer 2 - 4 Datagram
pub const Full = struct {
    l2_header: Layer2Header = .{ .eth = .{} },
    l3_header: Layer3 = .{ .ip = .{} },
    l4_header: ?Layer4 = .{ .udp = .{} },
    payload: []const u8 = "Hello World!",
    l2_footer: Layer2Footer = .{ .eth = .{} },

    /// Initialize a Full Datagram based on the given Headers, Payload, and Footer types.
    pub fn init(layer: u3, headers: []const []const u8, payload: []const u8, footer: []const u8) !@This() {
        const l_diff = 2 - @as(i4, @intCast(layer)); // Layer Difference. Aligns input headers based on given layer.
        return .{
            .l2_header = if (layer > 2) .{ .eth = .{} } else l2Hdr: {
                const l2_hdr_type = strToEnum(meta.Tag(Layer2Header), headers[0]) orelse return error.InvalidHeader;
                switch(l2_hdr_type) { 
                    inline else => |l2_hdr_tag| break :l2Hdr @unionInit(Layer2Header, @tagName(l2_hdr_tag), .{}),
                }
            },
            .l3_header = if (layer > 3) .{ .ip = .{} } else l3Hdr: {
                const l3_hdr_type = strToEnum(meta.Tag(Layer3), headers[@as(u3, @intCast(l_diff + 1))]) orelse return error.InvalidHeader;
                switch(l3_hdr_type) {
                    inline else => |l3_hdr_tag| break :l3Hdr @unionInit(Layer3, @tagName(l3_hdr_tag), .{}),
                }
            },
            .l4_header = l4Hdr: {
                const l4_hdr_type = strToEnum(meta.Tag(Layer4), headers[@as(u3, @intCast(l_diff + 2))]) orelse break :l4Hdr null;
                switch (l4_hdr_type) {
                    inline else => |l4_hdr_tag| break :l4Hdr @unionInit(Layer4, @tagName(l4_hdr_tag), .{}),
                }
            },
            .payload = payload,
            .l2_footer = if (layer > 2) .{ .eth = .{} } else l2Hdr: {
                const l2_ftr_type = strToEnum(meta.Tag(Layer2Footer), footer) orelse return error.InvalidFooter;
                switch(l2_ftr_type) { 
                    inline else => |l2_ftr_tag| break :l2Hdr @unionInit(Layer2Footer, @tagName(l2_ftr_tag), .{}),
                }
            },
        };
    }

    /// Perform various calculations (Length, Checksum, etc...) for each relevant field within this Datagram
    /// User must free.
    pub fn calcFromPayload(self: *@This(), alloc: mem.Allocator) !void {
        // Data Payload
        //const suffix = if (self.payload.len % 8 != 0) "\n" else "\n\u{0}";
        if (self.payload[self.payload.len - 1] != '\n') self.payload = try mem.concat(alloc, u8, &.{ self.payload, "\n" });
        var payload = @constCast(self.payload);

        // Layer 4 
        if (self.l4_header != null) {
            var l4_payload = switch (meta.activeTag(self.l3_header)) {
                .ip => l4Payload: {
                    var pseudo_hdr = Packets.IPPacket.SegmentPseudoHeader {
                        .src_ip_addr = self.l3_header.ip.src_ip_addr,
                        .dst_ip_addr = self.l3_header.ip.dst_ip_addr,
                        .protocol = @intCast(self.l3_header.ip.protocol),
                    };
                    break :l4Payload try mem.concat(alloc, u8, &.{ try pseudo_hdr.asNetBytesBFG(alloc), payload });
                },
                else => payload,
            };
            try self.l4_header.?.calc(alloc, l4_payload);
        }
        
        // Layer 3
        var l3_payload = if (self.l4_header == null) payload else try mem.concat(alloc, u8, &.{ try self.l4_header.?.asNetBytes(alloc), payload });
        try self.l3_header.calc(alloc, l3_payload);

        // Layer 2
        var l2_payload = try mem.concat(alloc, u8, &.{ try self.l2_header.asNetBytes(alloc), try self.l3_header.asNetBytes(alloc), l3_payload });
        try self.l2_footer.calc(alloc, l2_payload);
    }

    /// Returns this Datagram as a Byte Array in Network Byte Order / Big Endian. Network Byte Order words are 32-bits.
    /// User must free. TODO - Determine if freeing the returned slice also frees out_buf. (Copied from BitFieldGroup.zig)
    pub fn asNetBytes(self: *@This(), alloc: mem.Allocator) ![]u8 {
        var byte_buf = if (self.l4_header != null) 
            try mem.concat(alloc, u8, &.{ 
                try self.l2_header.asNetBytes(alloc), 
                try self.l3_header.asNetBytes(alloc), 
                try self.l4_header.?.asNetBytes(alloc), 
                self.payload, 
                try self.l2_footer.asNetBytes(alloc) 
            })
        else 
            try mem.concat(alloc, u8, &.{ 
                try self.l2_header.asNetBytes(alloc), 
                try self.l3_header.asNetBytes(alloc), 
                self.payload, 
                try self.l2_footer.asNetBytes(alloc) 
            });

        return byte_buf;
    }

    pub usingnamespace BFG.implBitFieldGroup(@This(), .{ .kind = .FRAME });
};

