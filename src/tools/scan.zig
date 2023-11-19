//! Scan a Network using ARP (Layer 2), ICMP (Layer 3), or TCP (Layer 4)

const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const time = std.time;

const lib = @import("../zinglib.zig");
const conn = lib.connect;
const craft = lib.craft;
const ia = lib.interact;
const rec = @import("record.zig");
const send = lib.send;
const utils = lib.utils;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;
const Frames = lib.Frames;
const Packets = lib.Packets;

/// Scan Protocols.
pub const ScanProtocols = enum{
    ARP,
    ICMP,
    TCP,
};

/// Scan Group. A group of Network Addresses and Booleans for Scanning a single target.
pub const ScanGroup = struct{
    mac: ?Addresses.MAC = null,
    ip: Addresses.IPv4,
    ip_scanned: bool = false,
    port_map: ?PortMap = null,
        
    /// A Map of Ports to be checked during Scanning.
    pub const PortMap = std.ArrayHashMap(
        u16,
        bool,
        struct{
            pub fn hash(_: @This(), port: u16) u32 { return @intCast(port); }
            pub fn eql(_: @This(), this: u16, that: u16, _: usize) bool { return this == that; }
        },
        false
    );
};

/// Scan List. A Thread-Safe Multi Array List of Scan Groups for use during Scanning.
pub const ScanList = struct{
    _list: std.MultiArrayList(ScanGroup) = std.MultiArrayList(ScanGroup){},
    _alloc: mem.Allocator,
    _mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// Initialize a new Scan List.
    pub fn init(alloc: mem.Allocator) @This() {
        return .{
            ._alloc = alloc,
        };
    }

    /// De-initialize this Scan List.
    pub fn deinit(self: *@This()) void {
        for (self._list.items(.port_map)) |*map| if (map.*) |_| self._alloc.destroy(map);
        self._list.deinit(self._alloc);
    }

    /// Add a new Scan Group to this Scan List.
    pub fn append(self: *@This(), group: ScanGroup) !void {
        self._mutex.lock();
        try self._list.append(self._alloc, group);
        self._mutex.unlock();
    }

    /// Use this Scan List exclusively.
    pub fn use(self: *@This()) *std.MultiArrayList(ScanGroup) {
        self._mutex.lock();
        return &(self._list);
    }

    /// Finish using this Scan List exclusively.
    pub fn finish(self: *@This()) void {
        self._mutex.unlock();
    }
};

/// Base Config for ScanConfig
const BaseScanConfig = struct{
    /// Ports to Scan (TCP Only).
    /// This can be given individually, as a comma-separated list, or as a '-' separated range.
    ports: ?[]const u8 = "22,80",
    /// The Protocal to Scan the Network on.
    proto: ?ScanProtocols = .ICMP,
    /// The MAC Address the scan should come from.
    /// Leaving this null uses the Interfaces current MAC Address
    mac_addr: ?[]const u8 = null,
    /// The IP Address the scan should come from.
    /// Leaving this null uses the Interfaces current IP Address
    ip_addr: ?[]const u8 = null,
    /// Datagram File
    /// The path to a Datagram File that will be sent for each Scan.
    datagram_file: ?[]const u8 = null,

    /// The IP Address(es) to Scan. 
    /// This can be given individually, as a comma-separated list, as a hyphen-separated range (on any one octet), or as a subnet in CIDR notation.
    scan_addr: []const u8,
};
/// Config for Scanning a Network.
pub const ScanConfig = utils.MergedStruct(&.{ rec.RecordConfig, BaseScanConfig });


/// Base Scan Context.
const BaseScanContext = struct{
    scan_proto: ScanProtocols = .ICMP,
    //scan_ips: ?[]Addresses.IPv4 = null,
    //scan_ports: ?[]u16 = null,
    scan_list: ScanList,
    out_dg: Datagrams.Full,
    send_sock: conn.IFSocket,
};
/// Scan Context
pub const ScanContext = utils.MergedStruct(&.{ rec.RecordContext, BaseScanContext });


/// Scan Datagrams.
pub fn scan(alloc: mem.Allocator, config: ScanConfig) !void {

    // Set up Scan
    var src_mac = if (config.mac_addr) |mac| try Addresses.MAC.fromStr(mac) else null;
    var send_sock = try conn.IFSocket.init(.{
        .if_name = config.if_name.?,
        .if_mac_addr = if (src_mac) |*mac| &@constCast(mac).toByteArray() else null,
    });
    if (src_mac == null) src_mac = try send_sock.getMAC();
    const src_ip = if (config.ip_addr) |ip| try Addresses.IPv4.fromStr(ip) else try send_sock.getIPv4();
    log.info(
        \\Scanner Addresses:
        \\ - MAC: {s}
        \\ - IPv4: {s}
        \\
        \\
        , .{
            try src_mac.?.toStr(alloc),
            try src_ip.toStr(alloc),
        }
    );
    
    var out_dg: Datagrams.Full, 
    const scan_ips: []Addresses.IPv4,
    const scan_ports: ?[]u16 =
        ctxConf: {
            switch (config.proto.?) {
                .ARP => {
                    var out_dg = 
                        if (config.datagram_file) |dg_file| try craft.decodeDatagram(alloc, dg_file)
                        else Datagrams.Full{
                            .l2_header = .{ .eth = .{
                                .dst_mac_addr = try Addresses.MAC.fromStr("FF:FF:FF:FF:FF:FF"),
                                .ether_type = Frames.EthFrame.Header.EtherTypes.ARP,
                            } },
                            .l3_header = .{ .arp = .{
                                .sender_hw_addr = try send_sock.getMAC(),
                                .sender_proto_addr = src_ip,
                            } },
                            .l4_header = null,
                            .payload = "",
                        };

                    if (src_mac) |mac| out_dg.l2_header.eth.src_mac_addr = mac;
                    break :ctxConf .{ 
                        out_dg,
                        Addresses.IPv4.sliceFromStr(alloc, config.scan_addr) catch {
                            log.err("ARP Scans require a valid IPv4 Address, IPv4 Address List, or IPv4 Subnet.", .{});
                            return error.InvalidIPv4;    
                        },
                        null,
                    };
                },
                .ICMP => {
                    var out_dg = 
                        if (config.datagram_file) |dg_file| try craft.decodeDatagram(alloc, dg_file)
                        else Datagrams.Full{
                            .l2_header = .{ .eth = .{
                                .dst_mac_addr = try Addresses.MAC.fromStr("FF:FF:FF:FF:FF:FF"),
                            } },
                            .l3_header = .{ .ip = .{
                                .src_ip_addr = src_ip,
                                .protocol = Packets.IPPacket.Header.Protocols.ICMP,
                            } },
                            .l4_header = .{ .icmp = .{
                                .icmp_type = Packets.ICMPPacket.Header.Types.ECHO,
                                .id = 42069,
                                .seq_num = 1,
                            } },
                            .payload = "abcdefghijklmnopqrstuvwabcdefghi",
                        };

                    if (src_mac) |mac| out_dg.l2_header.eth.src_mac_addr = mac;
                    break :ctxConf .{ 
                        out_dg,
                        Addresses.IPv4.sliceFromStr(alloc, config.scan_addr) catch {
                            log.err("ICMP Scans require a valid IPv4 Address, IPv4 Address List, or IPv4 Subnet.", .{});
                            return error.InvalidIPv4;    
                        },
                        null,
                    };
                },
                .TCP => {
                    var out_dg = 
                        if (config.datagram_file) |dg_file| try craft.decodeDatagram(alloc, dg_file)
                        else Datagrams.Full{
                            .l2_header = .{ .eth = .{
                                .dst_mac_addr = try Addresses.MAC.fromStr("FF:FF:FF:FF:FF:FF"),
                            } },
                            .l3_header = .{ .ip = .{
                                .src_ip_addr = src_ip,
                                .protocol = Packets.IPPacket.Header.Protocols.TCP,
                            } },
                            .l4_header = .{ .tcp = .{
                                .src_port = 54321,
                                .flags = @bitCast(Packets.TCPPacket.Header.Flags.SYN),
                            } },
                            .payload = "",
                        };

                    if (src_mac) |mac| out_dg.l2_header.eth.src_mac_addr = mac;
                    break :ctxConf .{ 
                        out_dg,
                        Addresses.IPv4.sliceFromStr(alloc, config.scan_addr) catch {
                            log.err("TCP Scans require a valid IPv4 Address, IPv4 Address List, or IPv4 Subnet.", .{});
                            return error.InvalidIPv4;    
                        },
                        Addresses.Port.sliceFromStr(alloc, config.ports orelse "") catch {
                            log.err("TCP Scans require a valid Port, Port Range, or Port List.", .{});
                            return error.InvalidTCP;
                        },
                    };
                },
            }
        };

    var scan_list = ScanList.init(alloc);
    for (scan_ips) |ip| {
        try scan_list.append(.{
            .ip = ip,
            .port_map = portMap: {
                if (scan_ports) |ports| {
                    var map = ScanGroup.PortMap.init(alloc);
                    for (ports) |port| try map.put(port, false);
                    break :portMap map;
                }
                else break :portMap null;
            },
        });
    }
    defer {
        //for (scan_list.use().items(.port_map)) |map| alloc.free(map orelse continue); 
        scan_list.deinit();
    }

    // Set up File Recording if applicable.
    var cwd = fs.cwd();
    var record_file = 
        if (config.filename) |filename| recFile: {
            const format = @tagName(config.format.?);
            const full_name = 
                if (ascii.endsWithIgnoreCase(filename, format)) filename
                else try fmt.allocPrint(alloc, "{s}.{s}", .{ filename, format });
            defer alloc.free(full_name);
            break :recFile try cwd.createFile(full_name, .{ .truncate = false });
        }
        else null;
    defer if (record_file) |file| file.close();
    var record_writer = if (record_file) |r_file| ia.InteractWriter(io.Writer(fs.File, os.WriteError, fs.File.write)).init(r_file.writer()) else null;

    // Set up Interaction Context
    var scan_ctx = ScanContext{
        .encode_fmt = config.format.?,
        .enable_print = config.stdout.?,
        .dg_sep = config.dg_sep.?,
        .record_file = &record_file,
        // TODO: Fix Pointer to Temporary?
        .record_writer = if (record_writer) |rec_w| @constCast(&rec_w) else null,

        .scan_proto = config.proto.?,
        .scan_list = scan_list,
        .out_dg = out_dg,
        .send_sock = send_sock,
    };

    // Start Scan
    try ia.interact(
        alloc, 
        &scan_ctx,
        .{ .if_name = config.if_name.? },
        .{
            .recv_dgs_max = config.recv_dgs_max.?,
            .multithreaded = config.multithreaded.?,
        },
        .{
            .start_fn = scanStart,
            .react_fn = scanReact, 
        },
    );
}

/// Scan Start Function.
fn scanStart(alloc: mem.Allocator, ctx: anytype) !void {
    if (@TypeOf(ctx) != *ScanContext) @compileError("This Start Function requires a Context of Type `ScanContext`.");

    log.info("Starting {s} scan...", .{ @tagName(ctx.scan_proto) });
    var list = ctx.scan_list.use();
    defer ctx.scan_list.finish();
    const ips = list.items(.ip);
    for (ips) |ip| {
        log.info("Sending ARP Request for {s}...", .{ try ip.toStr(alloc) });
        const arp_dg = Datagrams.Full{
            .l2_header = .{ .eth = .{
                .src_mac_addr = ctx.out_dg.l2_header.eth.src_mac_addr,
                .dst_mac_addr = try Addresses.MAC.fromStr("FF:FF:FF:FF:FF:FF"),
                .ether_type = Frames.EthFrame.Header.EtherTypes.ARP,
            } },
            .l3_header = .{ .arp = .{
                .sender_hw_addr = ctx.out_dg.l2_header.eth.src_mac_addr,
                .sender_proto_addr =
                   switch (ctx.out_dg.l3_header.?) {
                       .arp => ctx.out_dg.l3_header.?.arp.sender_proto_addr,
                       else => ctx.out_dg.l3_header.?.ip.src_ip_addr,
                   },
                .tgt_proto_addr = ip,
            } },
            .l4_header = null,
            .payload = "",
        };
        try send.sendDatagram(alloc, arp_dg, ctx.send_sock);
        log.debug("ARP Request Packet:\n\n{s}", .{ arp_dg });
    }
}

/// Scan Reaction Function.
fn scanReact(alloc: mem.Allocator, ctx: anytype, datagram: Datagrams.Full) !void {
    if (@TypeOf(ctx) != *ScanContext) @compileError("This Reaction Function requires a Context of Type `ScanContext`.");
    const stdout = io.getStdOut().writer();
    var record = false;

    const l3_hdr = datagram.l3_header orelse return;
    handleARP: {
        const arp: Packets.ARPPacket.Header = if (l3_hdr == .arp) l3_hdr.arp else break :handleARP;
        const op_code = arp.op_code; //mem.bigToNative(u16, arp.op_code);
        if (op_code != Packets.ARPPacket.Header.OpCodes.REPLY) break :handleARP;
        const reply_ip = arp.sender_proto_addr;
        const reply_mac = arp.sender_hw_addr;
        var list = ctx.scan_list.use();
        defer ctx.scan_list.finish();
        const tgt_ip, 
        const tgt_mac,
        const tgt_ports
            = for (list.items(.ip), list.items(.mac), list.items(.port_map)) |ip, *mac, port_map| {
                if (@as(u32, @bitCast(ip)) == @as(u32, @bitCast(reply_ip))) {
                    if (mac.*) |_| return;
                    mac.* = reply_mac;
                    break .{ ip, reply_mac, port_map };
                }
            } 
            else return;
        const mac_str, const ip_str = .{ try tgt_mac.toStr(alloc), try tgt_ip.toStr(alloc) };
        defer alloc.free(mac_str); 
        defer alloc.free(ip_str); 
        switch (ctx.scan_proto) {
            .ARP => {
                log.info("ARP Reply from {s} for {s}!", .{ mac_str, ip_str });
                record = true;
            },
            .ICMP => {
                log.info("ARP Reply from {s}. Pinging {s}...", .{ mac_str, ip_str });
                ctx.out_dg.l2_header.eth.dst_mac_addr = tgt_mac;
                ctx.out_dg.l3_header.?.ip.dst_ip_addr = tgt_ip;
                try send.sendDatagram(alloc, ctx.out_dg, ctx.send_sock);
                log.debug("Ping Request Packet:\n\n{s}", .{ ctx.out_dg });
            },
            .TCP => {
                ctx.out_dg.l2_header.eth.dst_mac_addr = tgt_mac;
                ctx.out_dg.l3_header.?.ip.dst_ip_addr = tgt_ip;
                log.info("ARP Reply from {s}. Sending TCP Packet to:", .{ mac_str });
                for (tgt_ports.?.keys()) |port| {
                    log.info("- {s}:{d}...", .{ ip_str, port });
                    ctx.out_dg.l4_header.?.tcp.dst_port = port;
                    try send.sendDatagram(alloc, ctx.out_dg, ctx.send_sock);
                }
                log.debug("TCP Packet:\n\n{s}", .{ ctx.out_dg });
            }
        }
    }
    
    if (l3_hdr == .ip) {
        const resp_ip = l3_hdr.ip.src_ip_addr;
        const resp_ip_str = try resp_ip.toStr(alloc);
        defer alloc.free(resp_ip_str);
        switch (ctx.scan_proto) {
            .ICMP => {
                const l4_hdr = datagram.l4_header orelse return; 
                if (l4_hdr != .icmp) return; 
                var list = ctx.scan_list.use();
                defer ctx.scan_list.finish();
                for (list.items(.ip), list.items(.ip_scanned)) |ip, *scanned| {
                    if (@as(u32, @bitCast(ip)) != @as(u32, @bitCast(resp_ip))) continue;
                    if (scanned.*) return;
                    scanned.* = true;
                    ctx.*.count += 1;
                    log.info("Ping response from '{s}'. Total responses: {d}", .{ resp_ip_str, ctx.count });
                    record = true;
                    break;
                }
            },
            .TCP => {
                const l4_hdr = datagram.l4_header orelse return; 
                if (
                    l4_hdr != .tcp or 
                    @as(u32, @bitCast(l3_hdr.ip.dst_ip_addr)) != @as(u32, @bitCast(ctx.out_dg.l3_header.?.ip.src_ip_addr))
                ) return; 
                const resp_port = l4_hdr.tcp.src_port; 
                var list = ctx.scan_list.use();
                defer ctx.scan_list.finish();
                for (list.items(.ip), list.items(.ip_scanned), list.items(.port_map)) |ip, *scanned, *port_map| {
                    if (@as(u32, @bitCast(ip)) != @as(u32, @bitCast(resp_ip))) continue;
                    scanned.* = true;
                    var all_ports = false;
                    for (port_map.*.?.keys(), port_map.*.?.values()) |port, *p_scanned| {
                        if (resp_port != port or p_scanned.*) continue;
                        if (!p_scanned.*) {
                            p_scanned.* = true;
                            ctx.*.count += 1;
                        }
                        var flagsList = std.ArrayList(u8).init(alloc);
                        defer flagsList.deinit();
                        inline for (meta.fields(Packets.TCPPacket.Header.Flag)) |flag| {
                            if (@field(l4_hdr.tcp.flags, flag.name)) 
                                try flagsList.writer().print("{s}|", .{ flag.name });
                        }
                        const resp_flags = try flagsList.toOwnedSlice();
                        defer alloc.free(resp_flags);
                        log.info("TCP response from '{s}:{d}'. Flags: '|{s}'. Total responses: {d}", .{ 
                            resp_ip_str, 
                            resp_port,
                            resp_flags,
                            ctx.count 
                        });
                        if (ctx.enable_print) try stdout.print("{s}\n{s}", .{ datagram, ctx.dg_sep });
                        all_ports = all_ports and p_scanned.*;
                        record = true;
                        if (all_ports) return;
                    }
                }
            },
            else => {},
        }
    }

    if (!record) return;
    if (ctx.record_file.*) |file| {
        try file.seekFromEnd(0);
        try craft.encodeDatagram(alloc, datagram, ctx.record_writer.?, ctx.encode_fmt);
        if (ctx.encode_fmt == .txt) try ctx.record_writer.?.print("{s}", .{ ctx.dg_sep });
    }
    if (ctx.enable_print) {
        try craft.encodeDatagram(alloc, datagram, stdout, ctx.encode_fmt);
        if (ctx.encode_fmt == .txt) try stdout.print("{s}", .{ ctx.dg_sep });
    }
    log.debug("Recorded Datagram #{d}.", .{ ctx.count });
}
