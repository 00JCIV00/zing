//! Datagram Union Templates

// Standard
const std = @import("std");
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;

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

    pub usingnamespace ImplCommonToAll(@This());
};

/// Layer 2 Footers
pub const Layer2Footer = union(enum) {
    eth: Frames.EthFrame.Footer,
    wifi: Frames.WifiFrame.Footer,

    pub usingnamespace ImplCommonToAll(@This());
};

/// Layer 3 Headers
pub const Layer3 = union(enum) {
    ip: Packets.IPPacket.Header,
    arp: Packets.ARPPacket.Header,

    pub usingnamespace ImplCommonToAll(@This());
};

/// Layer 4 Headers
pub const Layer4 = union(enum) {
    udp: Packets.UDPPacket.Header,
    tcp: Packets.TCPPacket.Header,
    icmp: Packets.ICMPPacket.Header,

    pub usingnamespace ImplCommonToAll(@This());
};

/// Common-to-All Datagram Functions
fn ImplCommonToAll(comptime T: type) type {
    return struct{
        /// Call the asBytes method of the inner BitFieldGroup.
        pub fn asBytes(self: *T, alloc: mem.Allocator) ![]u8 {
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
        pub fn asNetBytes(self: *T, alloc: mem.Allocator) ![]u8 {
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
pub const Full = struct{
    l2_header: Layer2Header = .{ .eth = .{} },
    l3_header: Layer3 = .{ .ip = .{} },
    l4_header: ?Layer4 = .{ .udp = .{} },
    payload: []const u8 = "Hello World!",
    l2_footer: Layer2Footer = .{ .eth = .{} },

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
                    log.debug("Ethernet Interface Detected.", .{});
                    const eth_hdr_end = @bitSizeOf(EthHeader) / 8;
                    var eth_hdr: EthHeader = @bitCast(frame_buf[0..eth_hdr_end].*);

                    const src_mac = eth_hdr.src_mac_addr;
                    const dst_mac = eth_hdr.dst_mac_addr;
                    const eth_type_raw = mem.bigToNative(u16, eth_hdr.ether_type);

                    const EthTypes = EthHeader.EtherTypes;
                    const eth_type = 
                        if (EthTypes.inEnum(eth_type_raw)) ethType: { 
                            switch (@as(EthTypes.Enum(), @enumFromInt(eth_type_raw))) {
                                inline else => |tag| break :ethType @tagName(tag),
                            }
                        }
                        else if (eth_type_raw <= 1500) "802.3 - Payload Size"
                        else "Unknown";

                    log.debug(
                        \\
                        \\LAYER 2: ETH
                        \\SRC MAC: {s}
                        \\DST MAC: {s}
                        \\ETH TYPE: {s}
                        \\
                        , .{
                            try src_mac.toStr(alloc),
                            try dst_mac.toStr(alloc),
                            eth_type,
                        }
                    );

                    datagram.l2_header = .{ .eth = eth_hdr };                
                    break :l2Hdr .{ 
                        frame_buf[eth_hdr_end..], 
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
        if (l3_type != EthHeader.EtherTypes.IPv4) {
            log.debug("Not an IPv4 Packet. Finished parsing.", .{});
            return error.UnimplementedType;
        }

        const IPHeader = lib.Packets.IPPacket.Header;
        const ip_hdr_end = (@bitSizeOf(IPHeader) / 8);
        var ip_hdr: IPHeader = @bitCast(l3_buf[0..ip_hdr_end].*);
        const l4_buf = l3_buf[ip_hdr_end..];

        const IPProtos = IPHeader.Protocols;
        const ip_proto = if (IPProtos.inEnum(ip_hdr.protocol)) ipProto: {
            break :ipProto switch (@as(IPProtos.Enum(), @enumFromInt(ip_hdr.protocol))) {
                inline else => |tag| @tagName(tag),
            };
        }
        else "UNKNOWN";

        log.debug(
            \\
            \\LAYER 3: IPv4
            \\SRC IP: {s}
            \\DST IP: {s}
            \\IP PROTO: {s}
            \\
            , .{
                try ip_hdr.src_ip_addr.toStr(alloc),
                try ip_hdr.dst_ip_addr.toStr(alloc),
                ip_proto,
            }
        );
        datagram.l3_header = .{ .ip = ip_hdr };

        // Layer 4
        if (!IPProtos.inEnum(ip_hdr.protocol)) return error.UnimplementedType;
        const payload_buf = switch (@as(IPProtos.Enum(), @enumFromInt(ip_hdr.protocol))) {
            .UDP => payload: {
                const UDPHeader = lib.Packets.UDPPacket.Header;
                const udp_hdr_end = (@bitSizeOf(UDPHeader) / 8);
                var udp_hdr: UDPHeader = @bitCast(l4_buf[0..udp_hdr_end].*);

                log.debug(
                    \\
                    \\LAYER 4: UDP
                    \\SRC PORT: {d}
                    \\DST PORT: {d}
                    \\
                    , .{
                        udp_hdr.src_port,
                        udp_hdr.dst_port,
                    }
                );

                datagram.l4_header = .{ .udp = udp_hdr };
                break :payload l4_buf[udp_hdr_end..];
            },
            .TCP => payload: {
                const TCPHeader = lib.Packets.TCPPacket.Header;
                const tcp_hdr_end = (@bitSizeOf(TCPHeader) / 8);
                var tcp_hdr: TCPHeader = @bitCast(l4_buf[0..tcp_hdr_end].*);

                log.debug(
                    \\
                    \\LAYER 4: TCP
                    \\SRC PORT: {d}
                    \\DST PORT: {d}
                    \\SEQ #: {d}
                    \\
                    , .{
                        tcp_hdr.src_port,
                        tcp_hdr.dst_port,
                        tcp_hdr.seq_num,
                    }
                );

                datagram.l4_header = .{ .tcp = tcp_hdr };
                break :payload l4_buf[tcp_hdr_end..];
            },
            .ICMP => payload: {
                const ICMPHeader = lib.Packets.ICMPPacket.Header;
                const icmp_hdr_end = (@bitSizeOf(ICMPHeader) / 8);
                var icmp_hdr: ICMPHeader = @bitCast(l4_buf[0..icmp_hdr_end].*);

                const ICMPTypes = ICMPHeader.Types;
                const icmp_type = if (ICMPTypes.inEnum(icmp_hdr.icmp_type)) icmpType: {
                    break :icmpType switch (@as(ICMPTypes.Enum(), @enumFromInt(icmp_hdr.icmp_type))) {
                        inline else => |tag| @tagName(tag),
                    };
                }
                else "UNKNOWN";

                const ICMPCodes = ICMPHeader.Codes;
                var code_buf: [50]u8 = .{ 0 } ** 50;
                const icmp_code = if (ICMPCodes.DEST_UNREACHABLE.inEnum(icmp_hdr.code)) icmpCode: {
                    break :icmpCode switch (@as(ICMPCodes.DEST_UNREACHABLE.Enum(), @enumFromInt(icmp_hdr.code))) {
                        inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "DEST UNREACHABLE - {s}", .{ @tagName(tag) })
                    };
                }
                else if (ICMPCodes.TIME_EXCEEDED.inEnum(icmp_hdr.code)) icmpCode: {
                    break :icmpCode switch (@as(ICMPCodes.TIME_EXCEEDED.Enum(), @enumFromInt(icmp_hdr.code))) {
                        inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "TIME EXCEEDED - {s}", .{ @tagName(tag) })
                    };
                }
                else if (ICMPCodes.REDIRECT.inEnum(icmp_hdr.code)) icmpCode: {
                    break :icmpCode switch (@as(ICMPCodes.REDIRECT.Enum(), @enumFromInt(icmp_hdr.code))) {
                        inline else => |tag| try std.fmt.bufPrint(code_buf[0..], "REDIRECT - {s}", .{ @tagName(tag) })
                    };
                }
                else "UNKNOWN";

                log.debug(
                    \\
                    \\LAYER 4: ICMP
                    \\TYPE: {s}
                    \\CODE: {s}
                    \\
                    , .{
                        icmp_type,
                        icmp_code,
                    }
                );

                datagram.l4_header = .{ .icmp = icmp_hdr };
                break :payload l4_buf[icmp_hdr_end..];
            },
            else => {
                log.debug("Not a parseable IP Protocol '{s}'. Finished parsing.", .{ ip_proto });
                return error.UnimplementedType;
            },
        };

        // Payload
        const payload_end = payload_buf.len - l2_footer_len;
        if (payload_end > 0) {
            log.debug(
                \\
                \\PAYLOAD (Size: {d}B):
                \\{s}
                \\
                , .{ 
                    payload_end,
                    payload_buf[0..payload_end],
                }
            );
            datagram.payload = payload_buf[0..payload_end];
        }
        else {
            log.debug("NO DEBUG", .{});
            datagram.payload = "";
        }

        // Footer
        const footer_buf = payload_buf[payload_end..(payload_end + 4)];
        switch(l2_type) {
            .eth => {
                const EthFooter = lib.Frames.EthFrame.Footer;
                var eth_footer: EthFooter = @bitCast(@as(*const [@sizeOf(EthFooter)]u8, @ptrCast(footer_buf)).*);

                log.debug(
                    \\
                    \\FOOTER: ETH
                    \\FCS: {d}
                    \\
                    , .{ eth_footer.eth_frame_check_seq }
                );

                datagram.l2_footer = .{ .eth = eth_footer };
            },
            .wifi => {},
        }

        return datagram;
    }

    pub usingnamespace BFG.ImplBitFieldGroup(@This(), .{ .kind = .FRAME });
};

