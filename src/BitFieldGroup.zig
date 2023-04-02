//! BitFieldGroup - Common-to-All functionality for BitField Groups (Frames, Packets, Headers, etc).

const std = @import("std");

/// Implementation function to be called with 'usingnamespace'.
pub fn implBitFieldGroup(comptime T: type, comptime impl_config: ImplConfig) type {
    return struct {
        pub const bfg_kind: Kind = impl_config.kind;
        pub const bfg_name = impl_config.name;

        /// Initialize a copy of the BitFieldGroup with an Encapsulated Header.
        pub fn initEncapHeader(comptime header: T.Header, comptime encap_header: anytype) !type {
            if (!@hasDecl(T, "Header")) {
                std.debug.print("The provided type '{s}' does not implement a 'Header'.", .{@typeName(T)});
                return error.NoHeaderImplementation;
            }

            const encap_type = @TypeOf(encap_header);

            return packed struct {
                const Self = @This();

                out_header: T.Header = header,
                in_header: encap_type = encap_header,

                pub usingnamespace implBitFieldGroup(Self, .{ .kind = T.bfg_kind, .name = T.bfg_name });
            };
        }

        /// Write the bits of each bitfield within a BitField Group in an IETF-like format.
        pub fn writeBitInfo(self: *T, writer: anytype, init_config: WriteBitInfoConfig) !WriteBitInfoConfig {
            var config = init_config;
            if (config.add_bit_ruler) {
                try writer.print("{s}", .{config.bit_ruler});
                config.add_bit_ruler = false;
            }
            if (!config.add_bitfield_title) {
                config.add_bitfield_title = switch (T.bfg_kind) {
                    Kind.BASIC => false,
                    else => true,
                };
            }
            if (config.add_bitfield_title) {
                const name = if (T.bfg_name.len > 0) T.bfg_name else @typeName(T);
                const new_line = newLine: {
                    if (config.col_idx != 0) {
                        config.col_idx = 0;
                        break :newLine "\n";
                    } else break :newLine "";
                };
                try writer.print("{s}    |-+-+-+{s: ^51}+-+-+-|\n", .{ new_line, name });
            }
            config.add_bitfield_title = false;

            const fields = std.meta.fields(T);
            inline for (fields) |field| {
                const f_self = @field(self.*, field.name);
                const field_info = @typeInfo(field.type);
                if ((field_info == .Struct) and @hasDecl(field.type, "writeBitInfo")) {
                    config.depth += 1;
                    config = try @constCast(&f_self).writeBitInfo(writer, config);
                } else {
                    const bits = try intToBitArray(f_self);
                    for (bits) |bit| {
                        if (config.col_idx == 0) try writer.print("{d:0>4}|", .{config.row_idx});
                        const gap: u8 = gapBlk: {
                            if (config.field_idx < bits.len - 1) {
                                config.field_idx += 1;
                                break :gapBlk ' ';
                            }
                            config.field_idx = 0;
                            break :gapBlk '|';
                        };
                        try writer.print("{b}{c}", .{ bit, gap });

                        config.col_idx += 1;

                        if (config.col_idx == 32) {
                            config.row_idx += 1;
                            config.col_idx = 0;
                            try writer.writeAll("\n");
                        }
                    }
                }
            }
            if (config.depth == 0) {
                const line_sep = if (config.col_idx != 0) "\n" else "";
                try writer.print("{s}{s}", .{ line_sep, config.bitfield_cutoff });
            } else config.depth -= 1;
            return config;
        }
    };
}

/// Implementation Config
const ImplConfig = struct {
    kind: Kind = Kind.BASIC,
    name: []const u8 = "",
};

/// Kinds of BitField Groups
pub const Kind = enum {
    BASIC,
    HEADER,
    PACKET,
    FRAME,
};

/// Config Struct for writeBitInfo()
const WriteBitInfoConfig = struct {
    add_bit_ruler: bool = false,
    add_bitfield_title: bool = false,
    row_idx: u16 = 0,
    col_idx: u6 = 0,
    field_idx: u16 = 0,
    depth: u8 = 0,
    bit_ruler: []const u8 =
        \\     0                   1                   2                   3   
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\    +---------------+---------------+---------------+---------------+
        \\
    ,
    bitfield_break: []const u8 = "    +---------------+---------------+---------------+---------------+\n",
    bitfield_cutoff: []const u8 = "END>+---------------+---------------+---------------+---------------+\n",

    //bit_ruler: []const u8 =
    //    \\                    B               B               B               B
    //    \\     0              |    1          |        2      |            3  |
    //    \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    \\    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    \\
    //,
    //bitfield_cutoff: []const u8 = "END>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n",
};

/// Convert an Integer to a BitArray of equivalent bits.
pub fn intToBitArray(int: anytype) ![@bitSizeOf(@TypeOf(int))]u1 {
    const int_type = @TypeOf(int);
    if (int_type == bool or int_type == u1) return [_]u1{@bitCast(u1, int)};
    if ((@typeInfo(int_type) != .Int)) {
        std.debug.print("\nType '{s}' is not an Integer.\n", .{@typeName(int_type)});
        return error.NotAnInteger;
    }
    var bit_ary: [@bitSizeOf(int_type)]u1 = undefined;
    inline for (&bit_ary, 0..) |*bit, idx|
        bit.* = @truncate(u1, (@bitReverse(int)) >> (idx));
    return bit_ary;
}
