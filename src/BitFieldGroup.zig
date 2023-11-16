//! BitFieldGroup - Common-to-All functionality for BitField Groups (Frames, Packets, Headers, etc).

const builtin = @import("builtin");
const cpu_endian = builtin.target.cpu.arch.endian();
const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

/// Config for a Bit Field Group Implementation 
const ImplBitFieldGroupConfig = struct{
    kind: Kind = Kind.BASIC,
    layer: u3 = 7,
    name: []const u8 = "",
};

/// Bit Field Group Implementation.
/// Add to a Struct with `usingnamespace`.
pub fn ImplBitFieldGroup(comptime T: type, comptime impl_config: ImplBitFieldGroupConfig) type {
    return struct{
        pub const bfg_kind: Kind = impl_config.kind;
        pub const bfg_layer: u3 = impl_config.layer;
        pub const bfg_name: []const u8 = impl_config.name;
            
        /// Returns this BitFieldGroup as a Byte Array Slice based on its bit-width (not its byte-width, which can differ for packed structs).
        pub fn asBytes(self: *T, alloc: mem.Allocator) ![]u8 {
            return try alloc.dupe(u8, mem.asBytes(self)[0..(@bitSizeOf(T) / 8)]);
        }

        /// Returns this BitFieldGroup as a Byte Array Slice with all Fields in Network Byte Order / Big Endian
        pub fn asNetBytesBFG(self: *T, alloc: mem.Allocator) ![]u8 {
            //if(cpu_endian == .little) try self.byteSwap();
            if(cpu_endian == .little) {
                var be_bits = try toBitsMSB(self.*);
                const BEBitsT = @TypeOf(be_bits);
                var be_buf: [@bitSizeOf(BEBitsT) / 8]u8 = undefined;
                mem.writeInt(BEBitsT, be_buf[0..], be_bits, .big);
                return try alloc.dupe(u8, be_buf[0..]);
            } 
            return self.asBytes(alloc); // TODO - change this to take the bits in LSB order
        }

        /// Byte Swap the BitFieldGroup's fields from Little Endian to Big Endian - TODO Allow this to switch to either Endianness
        pub fn byteSwap(self: *T) !void {
            // Check for and Handle provided Byte Bounds
            if (T.bfg_byte_bounds.len > 0) {
                var bytes = mem.asBytes(self)[0..(@bitSizeOf(T) / 8)];
                const self_int_type = meta.Int(.unsigned, @bitSizeOf(T));
                var bits: self_int_type = 0;
                var prev_bound = @as(u8, 0);
                inline for (T.bfg_byte_bounds, T.bfg_bounds_types) |bound, int_type| {
                    var bytes_slice = if (bound < bytes.len) bytes[prev_bound..bound] else bytes[prev_bound..];
                    var int_bits: int_type = mem.readIntSlice(int_type, bytes_slice, .Big); 
                    bits |= @as(self_int_type, @intCast(int_bits)) << (prev_bound * 8); // TODO - Fix this to work with lower bit-width ints (Currently breaks with a u64 UDP Header)

                    prev_bound = bound;
                }
                self.* = @as(T, @bitCast(bits));
                return;
            }

            // Handle all other scenarios - TODO Test this more thoroughly
            const fields = meta.fields(T);
            var skip: u16 = 0;
            inline for (fields, 0..) |field, idx| {
                _ = idx;
                if (skip > 0) {
                    skip -= 1;
                    //continue;
                }
                var field_self = @field(self.*, field.name);
                var field_ptr = &@field(self.*, field.name);
                const field_info = @typeInfo(field.type);
                switch (field_info) {
                    .Struct => {},//if(@hasDecl(field.type, "byteSwap")) try field_ptr.*.byteSwap(),
                    .Int => field_ptr.* = if (@bitSizeOf(field.type) % 8 == 0) @byteSwap(field_self) else field_self,
                    .Bool => {},
                    else => {
                        std.debug.print("Couldn't Byte Swap: {any}", .{ field_self });
                        return error.CouldNotByteSwap;
                    }
                }
            }
            return;
        }

        /// Checks if all the fields of this BitFieldGroup are Integers
        pub fn allInts(self: *T) bool {
            _ = self;
            const fields = meta.fields(T);
            inline for (fields) |field| if (@typeInfo(field.type) != .Int and @typeInfo(field.type) != .Bool) return false;
            return true;   
        }
        
        /// Format this BitFieldGroup for use by `std.fmt.format`.
        pub fn format(value: T, comptime _: []const u8, _: fmt.FormatOptions, writer: anytype) !void {
            var self = @constCast(&value);
            _ = try self.formatToText(writer, .{ .add_bit_ruler = true });
        }

        /// Format the bits of each bitfield within a BitField Group to an IETF-like format.
        pub fn formatToText(self: *T, writer: anytype, fmt_config: FormatToTextConfig) !FormatToTextConfig {
            const seps = FormatToTextSeparators{};
            var config = fmt_config;
            if (config.add_bit_ruler) {
                try writer.print("{s}", .{seps.bit_ruler_bin});
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
                var ns_buf: [100]u8 = undefined;
                const name_and_size = try fmt.bufPrint(ns_buf[0..], "{s} ({d}b | {d}B)", .{ name, @bitSizeOf(T), @bitSizeOf(T) / 8 });
                const prefix = setPrefix: {
                    if (config._col_idx != 0) {
                        config._col_idx = 0;
                        break :setPrefix "\n";
                    } else break :setPrefix "";
                };
                try writer.print(seps.bitfield_header, .{ prefix, name_and_size });
            }
            config.add_bitfield_title = false;

            const fields = meta.fields(T);
            inline for (fields) |field| {
                const field_self = @field(self.*, field.name);
                const field_info = @typeInfo(field.type);
                switch (field_info) {
                    .Struct => config = try fmtStruct(@constCast(&field_self), writer, config),
                    .Union => {
                        switch (meta.activeTag(field_self)) {
                            inline else => |tag| config = try fmtStruct(@constCast(&@field(field_self, @tagName(tag))), writer, config)
                        }
                    },
                    .Pointer => { //TODO Properly add support for Arrays?
                        var slice_upper_buf: [100]u8 = undefined;
                        try writer.print(seps.bitfield_header, .{ "", ascii.upperString(slice_upper_buf[0..field.name.len], field.name) });
                        if (config.enable_neat_strings or config.enable_detailed_strings) {
                            const slice = if (field_self.len > 0 and field_self[field_self.len - 1] == '\n') field_self[0..field_self.len - 1] else field_self;
                            try writer.print(seps.raw_data_bin, .{ "START RAW DATA" });
                            if (config.enable_neat_strings) {
                                var data_window = mem.window(u8, slice, 59, 59);
                                while (data_window.next()) |data| try writer.print(seps.raw_data_win_bin, .{ data });
                            }
                            if (config.enable_detailed_strings) {
                                for (slice, 0..) |elem, idx| {
                                    const elem_out = switch (elem) {
                                        '\n' => " NEWLINE",
                                        '\t' => " TAB",
                                        '\r' => " CARRIAGE RETURN",
                                        ' ' => " SPACE",
                                        '\u{0}' => " NULL",
                                        else => &[_:0]u8{ elem },
                                    };
                                    try writer.print(seps.raw_data_elem_bin, .{ idx, elem, elem, elem_out });
                                } 
                            }
                            try writer.print(seps.raw_data_bin, .{ "END RAW DATA" });
                        }
                        else try writer.print(seps.raw_data_bin, .{ "DATA OMITTED FROM OUTPUT" });

                    },
                    .Optional => { // TODO - Refactor this to properly handle .Struct, .Union, and .Int/.Bool 
                        _ = isNull: {
                            var field_raw = field_self orelse {
                                break :isNull true; 
                            };
                            config = switch (@typeInfo(@TypeOf(field_raw))) {
                                .Struct => try fmtStruct(&field_raw, writer, config),
                                .Union => switch (meta.activeTag(field_raw)) {
                                    inline else => |tag| try fmtStruct(&@field(field_raw, @tagName(tag)), writer, config),
                                },
                                else => break :isNull true,
                            };
                            break :isNull false;
                        };
                    },
                    .Int, .Bool => {
                        const bits = try intToBitArray(field_self);
                        for (bits) |bit| {
                            if (config._col_idx == 0) try writer.print("{d:0>4}|", .{config._row_idx});
                            const gap: u8 = gapBlk: {
                                if (config._field_idx < bits.len - 1) {
                                    config._field_idx += 1;
                                    break :gapBlk ' ';
                                }
                                config._field_idx = 0;
                                break :gapBlk '|';
                            };
                            try writer.print("{b}{c}", .{ bit, gap });

                            config._col_idx += 1;

                            if (config._col_idx == 32) {
                                config._row_idx += 1;
                                config._col_idx = 0;
                                try writer.writeAll("\n");
                            }
                        }
                    },
                    else => continue,
                }
            }
            if (config._depth == 0) {
                const line_sep = if (config._col_idx != 0) "\n" else "";
                try writer.print("{s}{s}", .{ line_sep, seps.bitfield_cutoff_bin });
            } else config._depth -= 1;
            return config;
        }

        // Help function for Structs
        fn fmtStruct(field: anytype, writer: anytype, config: FormatToTextConfig) !FormatToTextConfig {
            if (!@hasDecl(@TypeOf(field.*), "formatToText")) return config;
            var conf = config;
            conf._depth += 1;
            return try @constCast(field).formatToText(writer, conf);
        }
    };
}

/// Convert an Integer to a BitArray of equivalent bits in MSB Format.
pub fn intToBitArray(int: anytype) ![@bitSizeOf(@TypeOf(int))]u1 {
    const IntT = @TypeOf(int);
    if (IntT == bool or IntT == u1) return [_]u1{ @bitCast(int) };
    if ((@typeInfo(IntT) != .Int)) {
        std.debug.print("\nType '{s}' is not an Integer.\n", .{ @typeName(IntT) });
        return error.NotAnInteger;
    }
    var bit_ary: [@bitSizeOf(IntT)]u1 = undefined;
    inline for (&bit_ary, 0..) |*bit, idx|
        bit.* = @as(u1, @truncate((@bitReverse(int)) >> idx));
    return bit_ary;
}

/// Convert the provided Struct, Int, or Bool to an Int in MSB format
pub fn toBitsMSB(obj: anytype) !meta.Int(.unsigned, @bitSizeOf(@TypeOf(obj))) {
    const ObjT = @TypeOf(obj);
    return switch (@typeInfo(ObjT)) {
        .Bool => @bitCast(obj),
        .Int => obj,//@bitReverse(obj), 
        .Struct => structInt: {
            const obj_size = @bitSizeOf(ObjT);
            var bits_int: meta.Int(.unsigned, obj_size) = 0;
            var bits_width: math.Log2IntCeil(@TypeOf(bits_int)) = obj_size;
            const fields = meta.fields(ObjT);
            inline for (fields) |field| {
                var field_self = @field(obj, field.name);
                bits_width -= @bitSizeOf(@TypeOf(field_self));
                bits_int |= @as(@TypeOf(bits_int), @intCast(try toBitsMSB(field_self))) << @as(math.Log2Int(@TypeOf(bits_int)), @intCast(bits_width));
            }
            break :structInt bits_int;
        },
        else => {
            std.debug.print("\nType '{s}' is not an Integer, Bool, or Struct.\n", .{ @typeName(ObjT) });
            return error.NoConversionToMSB;
        },
    };
}

/// Config Struct for `formatToText`()
/// Note, this is also used as a Context between recursive calls.
const FormatToTextConfig = struct{
    /// Add a Bit Ruler to the formatted output.
    add_bit_ruler: bool = false,
    /// Add the Title of BitFieldGroups to the formatted output.
    add_bitfield_title: bool = false,
    /// Enable Neat `[]const u8` (strings) in the formatted output.
    enable_neat_strings: bool = true,
    /// Enable Detailed `[]const u8` (strings) in the formatted output.
    enable_detailed_strings: bool = false,

    /// Line Row Index while formatting.
    ///
    /// **INTERNAL USE**
    _row_idx: u16 = 0,
    /// Line Column Index while formatting.
    ///
    /// **INTERNAL USE**
    _col_idx: u6 = 0,
    /// BitFieldGroup Field Index while formatting.
    ///
    /// **INTERNAL USE**
    _field_idx: u16 = 0,
    /// BitFieldGroup Depth while formatting.
    ///
    /// **INTERNAL USE**
    _depth: u8 = 0,
};

/// Struct of Separators for `formatToText`()
const FormatToTextSeparators = struct{
    // Binary Separators
    bit_ruler_bin: []const u8 =
        \\     0                   1                   2                   3   
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\WORD+---------------+---------------+---------------+---------------+
        \\
    ,
    bitfield_break_bin: []const u8 = "    +---------------+---------------+---------------+---------------+\n",
    bitfield_cutoff_bin: []const u8 = "END>+---------------+---------------+---------------+---------------+\n",
    bitfield_header: []const u8 = "{s}    |-+-+-+{s: ^51}+-+-+-|\n",
    raw_data_bin: []const u8 = "    |{s: ^63}|\n",
    raw_data_elem_bin: []const u8 = "     > {d:0>4}: 0b{b:0>8} 0x{X:0>2} {s: <38}<\n",
    raw_data_win_bin: []const u8 = "     > {s: <60}<\n",
    // Decimal Separators - TODO
    // Hexadecimal Separators - TODO

    bit_ruler_bin_old: []const u8 =
        \\                    B               B               B               B
        \\     0              |    1          |        2      |            3  |
        \\     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        \\    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \\
    ,
    bitfield_cutoff_bin_old: []const u8 = "END>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n",
};


/// Kinds of BitField Groups
pub const Kind = enum {
    BASIC,
    OPTION,
    HEADER,
    PACKET,
    FRAME,
};

