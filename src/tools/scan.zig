//! Scan a Network using ARP (Layer 2), ICMP (Layer 3), or TCP (Layer 4)

const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
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
    datagram_file: ?[]const u8,

    /// The MAC or IP Address(es) to Scan. 
    /// This can be given individually, as a comma-separated list, or as a subnet in CIDR notation (IP Only).
    scan_addr: []const u8,
};
/// Config for Scanning a Network.
pub const ScanConfig = utils.MergedStruct(&.{ rec.RecordConfig, BaseScanConfig });


/// Base Scan Context.
const BaseScanContext = struct{
    scan_proto: ScanProtocols = .ICMP,
    scan_macs: ?[]Addresses.MAC = null,
    scan_ips: ?[]Addresses.IPv4 = null,
    scan_ports: ?[]u16 = null,
    out_dg: *Datagrams.Full,
    send_sock: conn.IFSocket,
};
/// Scan Context
pub const ScanContext = utils.MergedStruct(&.{ rec.RecordContext, BaseScanContext });


/// Scan Datagrams.
pub fn scan(alloc: mem.Allocator, config: ScanConfig) !void {

    // Set up Scan
    const src_mac = if (config.mac_addr) |mac| try Addresses.MAC.fromStr(mac) else null;
    var send_sock = try conn.IFSocket.init(.{
        .if_name = config.if_name.?,
        .if_mac_addr = if (src_mac) |*mac| &@constCast(mac).toByteArray() else null,
    });
    const src_ip = if (config.ip_addr) |ip| try Addresses.IPv4.fromStr(ip) else try send_sock.getIPv4();
    log.info(
        \\Scanner Addresses:
        \\ - MAC: {s}
        \\ - IPv4: {s}
        \\
        \\
        , .{
            try (src_mac orelse try send_sock.getMAC()).toStr(alloc),
            try src_ip.toStr(alloc),
        }
    );
    
    var out_dg: Datagrams.Full, 
    const scan_macs: ?[]Addresses.MAC,
    const scan_ips: ?[]Addresses.IPv4 =
        ctxConf: {
            switch (config.proto.?) {
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
                        null,
                        Addresses.IPv4.sliceFromStr(alloc, config.scan_addr) catch {
                            log.err("ICMP Scans require a valid IPv4 Address, IPv4 Address List, or IPv4 Subnet.", .{});
                            return error.InvalidIPv4;    
                        },
                    };
                },
                else => {
                    log.err("Only ICMP scanning is currently implemented.", .{});
                    return error.UnimplementedProtocol;
                }
            }
        };

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

        .scan_macs = scan_macs,
        .scan_ips = scan_ips,
        .out_dg = &out_dg,
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
    switch (ctx.scan_proto) {
        .ICMP => {
            for (ctx.scan_ips.?) |ip| {
                log.info("Sending ARP Request for {s}...", .{ try ip.toStr(alloc) });
                const arp_dg = Datagrams.Full{
                    .l2_header = .{ .eth = .{
                        .src_mac_addr = ctx.out_dg.l2_header.eth.src_mac_addr,
                        .dst_mac_addr = try Addresses.MAC.fromStr("FF:FF:FF:FF:FF:FF"),
                        .ether_type = Frames.EthFrame.Header.EtherTypes.ARP,
                    } },
                    .l3_header = .{ .arp = .{
                        .sender_hw_addr = ctx.out_dg.l2_header.eth.src_mac_addr,
                        .sender_proto_addr = ctx.out_dg.l3_header.ip.src_ip_addr,
                        .tgt_proto_addr = ip,
                    } },
                    .l4_header = null,
                    .payload = "",
                };
                try send.sendDatagram(alloc, arp_dg, ctx.send_sock);
                log.debug("ARP Request Packet:\n\n{s}", .{ arp_dg });
            }
        },
        else => unreachable,
    }
}

/// Scan Reaction Function.
fn scanReact(alloc: mem.Allocator, ctx: anytype, datagram: Datagrams.Full) !void {
    if (@TypeOf(ctx) != *ScanContext) @compileError("This Reaction Function requires a Context of Type `ScanContext`.");
    const stdout = io.getStdOut().writer();
    
    switch (ctx.scan_proto) {
        .ICMP => {
            handleARP: {
                const arp: Packets.ARPPacket.Header = if (datagram.l3_header == .arp) datagram.l3_header.arp else break :handleARP;
                const op_code = mem.bigToNative(u16, arp.op_code);
                if (op_code != Packets.ARPPacket.Header.OpCodes.REPLY) break :handleARP;
                const reply_ip = arp.sender_proto_addr;
                const reply_mac = arp.sender_hw_addr;
                const tgt_ip = for (ctx.scan_ips.?) |ip| { if (@as(u32, @bitCast(ip)) == @as(u32, @bitCast(reply_ip))) break ip; } else {
                    log.debug("Unrelated ARP Request.", .{});
                    break :handleARP;
                };
                const tgt_mac = reply_mac;
                const mac_str, const ip_str = .{ try tgt_mac.toStr(alloc), try tgt_ip.toStr(alloc) };
                defer { 
                    alloc.free(mac_str); 
                    alloc.free(ip_str); 
                }
                log.info("ARP Reply from {s}. Pinging {s}...", .{ mac_str, ip_str });
                ctx.out_dg.l2_header.eth.dst_mac_addr = tgt_mac;
                ctx.out_dg.l3_header.ip.dst_ip_addr = tgt_ip;
                try send.sendDatagram(alloc, ctx.out_dg.*, ctx.send_sock);
                log.debug("Ping Request Packet:\n\n{s}", .{ ctx.out_dg });
            }

            if ((datagram.l4_header orelse return) != .icmp) return; 
            const resp_ip = datagram.l3_header.ip.src_ip_addr;
            if (utils.indexOfEql(Addresses.IPv4, ctx.scan_ips.?, resp_ip)) |_| {
                ctx.*.count += 1;
                log.info("Ping response from '{s}'. Total responses: {d}", .{ try resp_ip.toStr(alloc), ctx.count });
                if (ctx.enable_print) try stdout.print("{s}\n{s}", .{ datagram, ctx.dg_sep });
            }
        },
        else => unreachable,
    }

    //if (ctx.record_file.*) |file| {
    //    try file.seekFromEnd(0);
    //    try craft.encodeDatagram(alloc, datagram, ctx.record_writer.?, ctx.encode_fmt);
    //    if (ctx.encode_fmt == .txt) try ctx.record_writer.?.print("{s}", .{ ctx.dg_sep });
    //}
    //if (ctx.enable_print) {
    //    try craft.encodeDatagram(alloc, datagram, stdout, ctx.encode_fmt);
    //    if (ctx.encode_fmt == .txt) try stdout.print("{s}", .{ ctx.dg_sep });
    //}
    //ctx.*.count += 1;
    //log.debug("Recorded Datagram #{d}.", .{ ctx.count });
}
