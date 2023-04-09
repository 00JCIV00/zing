//! Zing Library

/// Abstractions for commonly used Network Addresses.
pub const Addresses = @import("Addresses.zig");
/// BitFieldGroup - Common-to-All functionality for BitField Groups (Frames, Packets, Headers, etc).
pub const BitFieldGroup = @import("BitFieldGroup.zig");
/// Components of basic frame types. (Currently just Ethernet)
pub const Frames = @import("Frames.zig");
/// Components of the base Packet structure for IP, ICMP, TCP, and UDP packets.
pub const Packets = @import("Packets.zig");
/// Datagram Union Templates
pub const Datagrams = @import("Datagrams.zig");

/// Functions for Crafting Packets
pub const craft = @import("craft.zig");
