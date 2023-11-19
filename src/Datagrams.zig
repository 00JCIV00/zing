//! Datagram Union Templates

// Standard
const std = @import("std");
const fmt = std.fmt;
const log = std.log;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const strToEnum = meta.stringToEnum;

// Zing
const lib = @import("zinglib.zig");
const BFG = lib.BitFieldGroup;
const Frames = lib.Frames;
const Packets = lib.Packets;


/// Layer 2 Headers
pub const Layer2Header = union(enum){
    eth: Frames.EthFrame.Header,
    wifi: Frames.WifiFrame.Header,

    pub usingnamespace ImplCommonToAll(@This());
};
/// Layer 2 Options
pub const Layer2Option = union(enum){
    eth: Frames.EthFrame.Option,

    pub usingnamespace ImplCommonToAll(@This());
    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.OPTION, 
        .layer = 2,
    });
};
/// Layer 2 Footers
pub const Layer2Footer = union(enum){
    eth: Frames.EthFrame.Footer,
    wifi: Frames.WifiFrame.Footer,

    pub usingnamespace ImplCommonToAll(@This());
};

/// Layer 3 Headers
pub const Layer3Header = union(enum){
    ip: Packets.IPPacket.Header,
    arp: Packets.ARPPacket.Header,

    pub usingnamespace ImplCommonToAll(@This());
};
/// Layer 3a Headers
pub const Layer3A_Header = union(enum){
    ip: Packets.IPPacket.SegmentPseudoHeader,

    pub usingnamespace ImplCommonToAll(@This());
};
/// Layer 3 Options
pub const Layer3Option = union(enum){
    ip: Packets.IPPacket.Option,

    pub usingnamespace ImplCommonToAll(@This());
    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.OPTION, 
        .layer = 3,
    });
};

/// Layer 4 Headers
pub const Layer4Header = union(enum) {
    udp: Packets.UDPPacket.Header,
    tcp: Packets.TCPPacket.Header,
    icmp: Packets.ICMPPacket.Header,

    pub usingnamespace ImplCommonToAll(@This());
};
/// Layer 4 Options
pub const Layer4Option = union(enum){
    tcp: Packets.TCPPacket.Option,

    pub usingnamespace ImplCommonToAll(@This());
    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ 
        .kind = BFG.Kind.OPTION, 
        .layer = 4,
    });
};

/// Common-to-All Datagram Functions
fn ImplCommonToAll(comptime T: type) type {
    return struct{
        /// Call the asBytes method of the inner BitFieldGroup.
        pub fn asBytes(self: *const T, alloc: mem.Allocator) ![]u8 {
            return switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @field(self, @tagName(tag));
                    return 
                        if (@hasDecl(@TypeOf(bfg), "asBytes")) try bfg.asBytes(alloc)
                        else error.NoAsBytesMethod;
                },
            };
        }

        /// Call the asNetBytesBFG method of the inner BitFieldGroup.
        pub fn asNetBytes(self: *const T, alloc: mem.Allocator) ![]u8 {
            return switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @field(self, @tagName(tag));
                    return 
                        if (@hasDecl(@TypeOf(bfg), "asNetBytesBFG")) try bfg.asNetBytesBFG(alloc)
                        else error.NoAsBytesMethod;
                },
            };
        }


        /// Call the specific calc method of the inner BitFieldGroup.
        pub fn calc(self: *T, alloc: mem.Allocator, pre: ?[]const u8, opts_len: u16, payload: []u8) !void {
            switch (meta.activeTag(self.*)) {
                inline else => |tag| {
                    var bfg = @constCast(&@field(self, @tagName(tag)));
                    if (@hasDecl(@TypeOf(bfg.*), "calcLengthAndChecksum")) try bfg.calcLengthAndChecksum(alloc, pre, opts_len, payload)
                    else if (@hasDecl(@TypeOf(bfg.*), "calcCRC")) try bfg.calcCRC(alloc, payload)
                    else return error.NoCalcMethod;
                },
            }
            return;
        }
    };
}


/// Full Layer 2 - 4 Datagram
pub const Full = struct{
    l2_header: Layer2Header = .{ .eth = .{} },
    l2_options: ?[]Layer2Option = null,
    l3_header: ?Layer3Header = .{ .ip = .{} },
    l3_options: ?[]Layer3Option = null,
    l4_header: ?Layer4Header = .{ .udp = .{} },
    l4_options: ?[]Layer4Option = null,
    payload: []const u8 = "Hello World!",
    l2_footer: ?Layer2Footer = .{ .eth = .{} },

    /// Initialize a Full Datagram based on the given Headers, Payload, and Footer types.
    pub fn init(layer: u3, headers: []const []const u8, payload: []const u8, footer: []const u8) !@This() {
        const l_diff = 2 - @as(i4, @intCast(layer)); // Layer Difference. Aligns input headers based on given layer.
        return .{
            .l2_header = if (layer > 2 and headers.len < 3) .{ .eth = .{} } else l2Hdr: {
                const l2_hdr_type = strToEnum(meta.Tag(Layer2Header), headers[0]) orelse return error.InvalidHeader;
                switch(l2_hdr_type) { 
                    inline else => |l2_hdr_tag| break :l2Hdr @unionInit(Layer2Header, @tagName(l2_hdr_tag), .{}),
                }
            },
            .l3_header = if (layer > 3 and headers.len < 2) .{ .ip = .{} } else l3Hdr: {
                const l3_hdr_type = strToEnum(meta.Tag(Layer3Header), headers[@as(u3, @intCast(l_diff + 1))]) orelse return error.InvalidHeader;
                switch(l3_hdr_type) {
                    inline else => |l3_hdr_tag| break :l3Hdr @unionInit(Layer3Header, @tagName(l3_hdr_tag), .{}),
                }
            },
            .l4_header = l4Hdr: {
                const l4_hdr_type = strToEnum(meta.Tag(Layer4Header), headers[@as(u3, @intCast(l_diff + 2))]) orelse break :l4Hdr null;
                switch (l4_hdr_type) {
                    inline else => |l4_hdr_tag| break :l4Hdr @unionInit(Layer4Header, @tagName(l4_hdr_tag), .{}),
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
        if (self.payload.len > 0 and self.payload[self.payload.len - 1] != '\n') self.payload = try mem.concat(alloc, u8, &.{ self.payload, "\n" });
        var payload = @constCast(self.payload);

        // Layer 4 
        if (self.l4_header) |_| {
            const l3a_hdr: ?Layer3A_Header = l3aHdr: {
                const l3_hdr = if (self.l3_header) |hdr| hdr else break :l3aHdr null;
                break :l3aHdr switch (meta.activeTag(l3_hdr)) {
                    .ip => .{ .ip = .{
                        .src_ip_addr = l3_hdr.ip.src_ip_addr,
                        .dst_ip_addr = l3_hdr.ip.dst_ip_addr,
                        .protocol = @intCast(l3_hdr.ip.protocol),
                    } },
                    else => null,
                };
            };
            var l3a_hdr_bytes: []const u8 =
                if (l3a_hdr) |p_hdr| try p_hdr.asNetBytes(alloc)
                else &.{};
            const opts_len: u16,
            var l4_payload = 
                if (self.l4_options) |opts| l4Payload: {
                    if (opts.len == 0) break :l4Payload .{ @intCast(opts.len), payload };
                    var pl_list = std.ArrayList(u8).init(alloc);
                    for (opts) |*opt| try pl_list.appendSlice(try @constCast(opt).asNetBytes(alloc));
                    try pl_list.appendSlice(payload);
                    break :l4Payload .{ @intCast(opts.len), try pl_list.toOwnedSlice() };
                }
                else .{ 0, payload };
            try self.l4_header.?.calc(alloc, l3a_hdr_bytes, opts_len, l4_payload);
        }
        
        // Layer 3
        var l3_payload: []u8 = if (self.l3_header) |_| l3Payload: {
            const opts_len: u16,
            const l3_opts =
                if (self.l3_options) |opts| .{
                    @intCast(opts.len),
                    l3Opts: { 
                        var opts_list = std.ArrayList(u8).init(alloc);
                        for (opts) |*opt| try opts_list.appendSlice(try @constCast(opt).asNetBytes(alloc));
                        break :l3Opts try opts_list.toOwnedSlice();
                    },
                }
                else .{ 0, &.{} };

            var l3_pl = 
                if (self.l4_header) |_| try mem.concat(alloc, u8, &.{ 
                    l3_opts,
                    try self.l4_header.?.asNetBytes(alloc), 
                    payload,
                }) 
                else payload;
            try self.l3_header.?.calc(alloc, &.{}, opts_len, l3_pl);
            break :l3Payload l3_pl;
        }
        else &.{};

        // Layer 2
        if (self.l2_footer) |_| {
            var l2_payload = 
                if (self.l3_header) |_| try mem.concat(alloc, u8, &.{ 
                    try self.l2_header.asNetBytes(alloc), 
                    try self.l3_header.?.asNetBytes(alloc), 
                    l3_payload,
                })
                else try mem.concat(alloc, u8, &.{
                    try self.l2_header.asNetBytes(alloc),
                    payload,
                });
                    
            try self.l2_footer.?.calc(alloc, &.{}, 0, l2_payload);
        }
    }

    /// Returns this Datagram as a Byte Array in Network Byte Order / Big Endian. Network Byte Order words are 32-bits.
    /// User must free. TODO - Determine if freeing the returned slice also frees out_buf. (Copied from BitFieldGroup.zig)
    pub fn asNetBytes(self: *const @This(), alloc: mem.Allocator) ![]u8 {
        var bytes_list = std.ArrayList(u8).init(alloc);
        try bytes_list.appendSlice(try self.l2_header.asNetBytes(alloc)); 
        if (self.l3_header) |l3_hdr| try bytes_list.appendSlice(try l3_hdr.asNetBytes(alloc));
        if (self.l3_options) |l3_opts|
            for (l3_opts) |opt| try bytes_list.appendSlice(try opt.asNetBytes(alloc));
        if (self.l4_header) |l4_hdr| try bytes_list.appendSlice(try l4_hdr.asNetBytes(alloc));
        if (self.l4_options) |l4_opts|
            for (l4_opts) |opt| try bytes_list.appendSlice(try opt.asNetBytes(alloc));
        try bytes_list.appendSlice(self.payload); 
        if (self.l2_footer) |l2_ftr| try bytes_list.appendSlice(try l2_ftr.asNetBytes(alloc));

        return try bytes_list.toOwnedSlice();
    }

    /// Creates a Full Datagram from the provided Frame Buffer (`frame_buf`) bytes.
    pub fn fromBytes(alloc: mem.Allocator, frame_buf: []const u8, l2_type: meta.Tag(Layer2Header)) !@This() {
        //var datagram = try alloc.create(@This());
        var datagram: @This() = undefined;

        // Layer 2
        const EthHeader = lib.Frames.EthFrame.Header;
        // TODO: Convert each Layer and sub-Type to their own functions since slice indexes must be compile time known.
        const l3_buf, const l3_type, const l2_footer_len: usize = l2Hdr: {
            switch (l2_type) {
                .eth => {
                    var eth_frame = Frames.EthFrame.from(frame_buf);
                    const eth_type_raw = mem.bigToNative(u16, eth_frame.header.ether_type);
                    datagram.l2_header = .{ .eth = eth_frame.header };
                    break :l2Hdr .{ 
                        frame_buf[eth_frame.len..],
                        eth_type_raw, 
                        @bitSizeOf(lib.Frames.EthFrame.Footer) / 8,
                    };
                },
                else => |tag| {
                    log.err("Unparseable Layer 2 Type '{s}'.", .{ @tagName(tag) });
                    return error.UnimplementedType;
                },
            }
        };

        // Layer 3
        if (!EthHeader.EtherTypes.inEnum(l3_type)) return error.UnimplementedType;
        const payload_buf = switch (@as(EthHeader.EtherTypes.Enum(), @enumFromInt(l3_type))) {
            .IPv4 => ipv4Payload: {
                const ip_packet = try Packets.IPPacket.from(alloc, l3_buf[0..]);
                const l4_buf = l3_buf[ip_packet.len..];

                const IPProtos = Packets.IPPacket.Header.Protocols;
                datagram.l3_header = .{ .ip = ip_packet.header };
                if (ip_packet.options) |opts| datagram.l3_options = @ptrCast(opts);
                //if (ip_packet.pseudo_header) |p_hdr| datagram.l3a_header = .{ .ip = p_hdr };

                // Layer 4
                if (!IPProtos.inEnum(ip_packet.header.protocol)) return error.UnimplementedType;
                break :ipv4Payload switch (@as(IPProtos.Enum(), @enumFromInt(ip_packet.header.protocol))) {
                    .UDP => payload: {
                        const UDPHeader = lib.Packets.UDPPacket.Header;
                        const udp_hdr_end = (@bitSizeOf(UDPHeader) / 8);
                        var udp_hdr = mem.bytesToValue(UDPHeader, l4_buf[0..udp_hdr_end]);
                        datagram.l4_header = .{ .udp = udp_hdr };
                        break :payload l4_buf[udp_hdr_end..];
                    },
                    .TCP => payload: {
                        var tcp_packet = try Packets.TCPPacket.from(alloc, l4_buf[0..]);
                        datagram.l4_header = .{ .tcp = tcp_packet.header };
                        if (tcp_packet.options) |opts| datagram.l4_options = @ptrCast(opts);
                        break :payload l4_buf[tcp_packet.len..];
                    },
                    .ICMP => payload: {
                        const ICMPHeader = lib.Packets.ICMPPacket.Header;
                        const icmp_hdr_end = (@bitSizeOf(ICMPHeader) / 8);
                        var size_buf: [@sizeOf(ICMPHeader)]u8 = .{ 0 } ** @sizeOf(ICMPHeader);
                        for (size_buf[0..icmp_hdr_end], l4_buf[0..icmp_hdr_end]) |*s, b| s.* = b;
                        //var icmp_hdr: ICMPHeader = @bitCast(l4_buf[0..icmp_hdr_end].*);
                        var icmp_hdr = mem.bytesToValue(ICMPHeader, size_buf[0..]);
                        datagram.l4_header = .{ .icmp = icmp_hdr };
                        break :payload l4_buf[icmp_hdr_end..];
                    },
                    else => {
                        //log.warn("Not a parseable IP Protocol '{s}'. Finished parsing.", .{ ip_proto });
                        return error.UnimplementedType;
                    },
                };
            },
            .ARP => arpPayload: {
                const ARPHeader = lib.Packets.ARPPacket.Header;
                const arp_hdr_end = (@bitSizeOf(ARPHeader) / 8);
                var size_buf: [@sizeOf(ARPHeader)]u8 = .{ 0 } ** @sizeOf(ARPHeader);
                for (size_buf[0..arp_hdr_end], l3_buf[0..arp_hdr_end]) |*s, b| s.* = b;
                //var arp_hdr: ARPHeader = @bitCast(l3_buf[0..arp_hdr_end].*);
                var arp_hdr = mem.bytesToValue(ARPHeader, size_buf[0..]);

                datagram.l3_header = .{ .arp = arp_hdr };
                datagram.l4_header = null;
                datagram.payload = "";
                break :arpPayload l3_buf[arp_hdr_end..];
            },
            else => {
                //log.warn("Not a parseable Ethernet Protocol '{d}'. Finished parsing.", .{ l3_type });
                return error.UnimplementedType;
            },
        };

        // Payload
        const footer_diff: i128 = @as(i64, @intCast(payload_buf.len)) - @as(i64, @intCast(l2_footer_len));
        if (footer_diff < 0) {
            if (datagram.l3_header) |l3_hdr| pl: {
                switch (l3_hdr) {
                    .arp => {
                        datagram.payload = "";
                        return datagram;
                    },
                    else => break :pl,
                }
            }
            log.err("End of Packet Buffer is {d}B too small for the Footer.", .{ -1 * footer_diff }); 
            return error.UnexpectedlySmallBuffer;
        }
        const payload_end = payload_buf.len - l2_footer_len;
        datagram.payload = if (payload_end > 0) payload_buf[0..payload_end] else "";

        // Footer
        const footer_buf = payload_buf[payload_end..(payload_end + 4)];
        switch(l2_type) {
            .eth => {
                const EthFooter = lib.Frames.EthFrame.Footer;
                var size_buf: [@sizeOf(EthFooter)]u8 = .{ 0 } ** @sizeOf(EthFooter);
                for (size_buf[0..4], footer_buf[0..4]) |*s, b| s.* = b;
                //var eth_footer: EthFooter = @bitCast(@as(*const [@sizeOf(EthFooter)]u8, @ptrCast(footer_buf)).*);
                var eth_footer = mem.bytesToValue(EthFooter, size_buf[0..]);

                datagram.l2_footer = .{ .eth = eth_footer };
            },
            .wifi => {},
        }

        return datagram;
    }

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = .FRAME });
};

