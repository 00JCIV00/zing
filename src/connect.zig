//! Functions for Connecting to Interfaces.

const std = @import("std");
const fs = std.fs;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;
const time = std.time;

const lib = @import("zinglib.zig");
const consts = lib.constants;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;


/// A Socket to an Interface.
pub const IFSocket = struct{
    /// Socket Descriptor.
    desc: os.socket_t,
    /// Interface Name.
    if_name: []const u8,
    /// Interface Hardware Family.
    hw_fam: u16, 

    /// Config for Initializing an Interface Socket.
    pub const IFSocketInitConfig = struct{
        /// Interface Name.
        if_name: []const u8 = "eth0",
        /// Interface MAC Address.
        if_mac_addr: ?[]const u8 = null,
    };

    /// Create a Socket Connection to an Interface (`if_name`).
    pub fn init(config: IFSocketInitConfig) !@This() {
        // Setup Socket
        var if_sock = os.socket(os.linux.AF.PACKET, os.linux.SOCK.RAW, consts.ETH_P_ALL) catch {
            log.err("There was an error connecting to the Interface. You may need to run with root privileges.", .{});
            return error.CouldNotConnectToInterface;
        };
        var if_name_ary: [16]u8 = .{ 0 } ** 16;
        mem.copy(u8, if_name_ary[0..], config.if_name);

        // - Interface Request
        var if_req = mem.zeroes(os.ifreq);
        if_req.ifrn.name = if_name_ary;

        // - Request Interface Family
        const ioctl_num = os.linux.ioctl(if_sock, consts.SIOCGIFHWADDR, @intFromPtr(&if_req));
        if (ioctl_num != 0) {
            log.err("There was an issue getting the Hardware info for Interface '{s}': '{d}'.", .{ config.if_name, ioctl_num });
            return error.CouldNotGetInterfaceInfo;
        }
        const hw_fam = if_req.ifru.hwaddr.family;

        // - Interface Address
        var if_addr = os.sockaddr.ll{
            .family = os.linux.AF.PACKET,
            .protocol = consts.ETH_P_ALL,
            .pkttype = consts.PACKET_HOST,
            .halen = 6,
            .hatype = hw_fam,
            .addr =
                if (config.if_mac_addr) |mac| customMAC: {
                    if (mac.len > 8) return error.CustomMACTooLong;
                    // 8-byte MAC Formatted for `os.sockaddr.ll`
                    if (mac.len == 8 ) break :customMAC mac[0..8].*;
                    // 6-byte normal MAC
                    var custom_mac: [8]u8 = .{ 0x0 } ** 8;
                    for (custom_mac[0..(mac.len)], mac) |*c, m| c.* = m;
                    break :customMAC custom_mac;
                }
                else if_req.ifru.hwaddr.data[0..8].*,
            .ifindex = ifIdx: {
                // Request Interface Index
                try os.ioctl_SIOCGIFINDEX(if_sock, &if_req);
                break :ifIdx if_req.ifru.ivalue;
            },
        };

        // - Bind to Socket
        os.bind(if_sock, @as(*os.linux.sockaddr, @ptrCast(&if_addr)), @sizeOf(@TypeOf(if_addr))) catch return error.CouldNotConnectToInterface;

        return .{
            .desc = if_sock,
            .if_name = config.if_name,
            .hw_fam = hw_fam,
        };
    }

    /// Close this Interface Socket.
    pub fn close(self: *const @This()) void {
        os.closeSocket(self.desc);
    }

    /// Get the MAC Address of this Interface if it has one.
    pub fn getMAC(self: *const @This()) !Addresses.MAC {
        var if_name_ary: [16]u8 = .{ 0 } ** 16;
        mem.copy(u8, if_name_ary[0..], self.if_name);
        var if_req = mem.zeroes(os.ifreq);
        if_req.ifrn.name = if_name_ary;
        const ioctl_num = os.linux.ioctl(self.desc, consts.SIOCGIFHWADDR, @intFromPtr(&if_req));
        if (ioctl_num != 0) {
            log.err("There was an issue getting the Hardware info for Interface '{s}': '{d}'.", .{ self.if_name, ioctl_num });
            return error.CouldNotGetInterfaceInfo;
        }
        return @bitCast(if_req.ifru.hwaddr.data[0..6].*);
    }

    /// Get the IPv4 Address of this Interface if it has one.
    pub fn getIPv4(self: *const @This()) !Addresses.IPv4 {
        var inet_sock = try os.socket(os.linux.AF.INET, os.linux.SOCK.DGRAM, 0);
        defer os.close(inet_sock);
        var if_name_ary: [16]u8 = .{ 0 } ** 16;
        mem.copy(u8, if_name_ary[0..], self.if_name);
        var if_req = mem.zeroes(os.ifreq);
        if_req.ifrn.name = if_name_ary;
        const ioctl_num = os.linux.ioctl(inet_sock, consts.SIOCGIFADDR, @intFromPtr(&if_req));
        if (ioctl_num != 0) {
            log.err("There was an issue getting the IP Address info for Interface '{s}': '{d}'.", .{ self.if_name, ioctl_num });
            return error.CouldNotGetInterfaceInfo;
        }
        return @bitCast(@as(os.linux.sockaddr.in, @bitCast(if_req.ifru.addr)).addr);
    }


    /// Set Promiscuous Mode for this Interface Socket.
    pub fn setPromiscuous(self: *const @This()) !void {
        var ifr_flags = mem.zeroes(os.ifreq);
        ifr_flags.ifrn.name = self.if_name;
        ifr_flags.ifru.flags |= consts.IFF_ALLMULTI;
        const set_prom = os.linux.ioctl(self, consts.SIOCSIFFLAGS, @intFromPtr(&ifr_flags));
        if (set_prom != 0) {
            log.err("There was an issue opening the socket in Promiscuous Mode:\n{d}\n", .{ os.errno(set_prom) });
            return error.CouldNotOpenPromiscuous;
        }
        else log.debug("Opened Promiscuous Mode!\n", .{});
        defer {
            ifr_flags.ifru.flags &= ~consts.IFF_ALLMULTI;
            _ = os.linux.ioctl(self.desc, consts.SIOCSIFFLAGS, @intFromPtr(&ifr_flags));
        }
    }
};
