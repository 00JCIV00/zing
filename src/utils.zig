//! Utility functions for the Zing Library

const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const mem = std.mem;
const meta = std.meta;

/// Create an `Enumerable` Implementation for any struct whose fields are all of the same Type.
pub fn ImplEnumerable(comptime T: type) type {
    const type_info = @typeInfo(T);
    if (type_info == .Enum) return T;
    if (type_info != .Struct and type_info != .Union) @compileError("The Enumerable Implementation can only be applied to Structs and Unions.");
    const type_decls = meta.declarations(T);
    const TagT = @TypeOf(@field(T, type_decls[0].name));
    if (@typeInfo(TagT) != .Int) @compileError("The Enumerable Implementation requires that all declarations be an Integer (any signedness) of the same Type.");
    for (type_decls) |decl| {
        const decl_val = @field(T, decl.name);
        if (@TypeOf(decl_val) != TagT) 
            @compileError("The Enumerable Implementation requires that all declarations be an Integer (any signedness) of the same Type.");
    }
    return struct{
        /// Return this Struct or Union as an Enum.
        pub fn Enum() type {
            var enum_fields: [type_decls.len]std.builtin.Type.EnumField = undefined;
            for (type_decls, enum_fields[0..]) |decl, *field| {
                field.* = .{
                    .name = decl.name,
                    .value = @field(T, decl.name),
                };
            }
            return @Type(std.builtin.Type{
                .Enum = .{
                    .tag_type = TagT,
                    .fields = enum_fields[0..],
                    .decls = &.{},
                    .is_exhaustive = true,
                }
            });
        }

        pub fn inEnum(value: TagT) bool {
            return for (std.enums.values(Enum())) |e_val| {
                if (value == @intFromEnum(e_val)) break true;
            }
            else false;
        }
    };
}

/// An Interface for Iterators.
pub fn Iterator(comptime ChildT: type) type { 
    return struct{
        /// A Pointer to the underlying Iterator Implementation.
        ptr: *anyopaque,
        /// The `next()` function of the underlying Iterator Implementation.
        next_fn: *const fn(*anyopaque) ?[]const ChildT,

        /// Call the `next()` function of the underlying Iterator Implementation.
        pub fn next(self: *@This()) ?[]const ChildT {
            return self.next_fn(self.ptr);
        }

        /// Get a generic Iterator from the Pointer (`ptr`) of an Iterator Implementation.
        pub fn from(ptr: anytype) @This() {
            const PtrT = @TypeOf(ptr);
            const ptr_info = @typeInfo(PtrT);
            if (ptr_info != .Pointer or ptr_info.Pointer.size != .One) 
                @compileError("The Iterator Interface requires a single-item Pointer to a Struct, but a '" ++ @typeName(PtrT) ++ "' was provided.");
            const IterT = ptr_info.Pointer.child;
            const required_fns = .{ "next" };
            inline for (required_fns) |req_fn| {
                comptime {
                    if (!meta.hasFn(IterT, req_fn))
                    @compileError("The '" ++ @typeName(IterT) ++ "' Type does not have the required function '" ++ req_fn ++ "()' for the Iterator Interface.");
                }
            }
            return .{    
                .ptr = @constCast(ptr),
                .next_fn = struct{
                    pub fn next(self_ptr: *anyopaque) ?[]const u8 {
                        var self: PtrT = @ptrCast(@alignCast(self_ptr));
                        return self.next();
                    }
                }.next,
            };
        }
    };
}

/// Merge Fields from all given Structs using comptime reification.
/// Note this only works for Structs without Declarations.
pub fn MergedStruct(comptime types: []const type) type {
    var base_info = @typeInfo(types[0]);
    if (base_info != .Struct) @compileError("All Merged Meta Types must be Structs!");
    for (types[1..]) |AddT| {
        if (@typeInfo(AddT) != .Struct) @compileError("All Merged Meta Types must be Structs!");
        base_info.Struct.fields = base_info.Struct.fields ++ meta.fields(AddT);
    }
    return @Type(.{ .Struct = base_info.Struct });
}


/// Find the Index of any Type, Scalar or Slice, (`needle`) within a Slice of that Type (`haystack`). (Why is this not in std.mem?!?!? Did I miss it?)
/// (Borrowed from Cova. Make a Utils Library?)
pub fn indexOfEql(comptime T: type, haystack: []const T, needle: T) ?usize {
    switch (@typeInfo(T)) {
        .Pointer => |ptr| {
            for (haystack, 0..) |hay, idx| if (mem.eql(ptr.child, hay, needle)) return idx;
            return null;
        },
        .Struct => {
            for (haystack, 0..) |hay, idx| if (meta.eql(hay, needle)) return idx;
            return null;
        },
        inline else => return mem.indexOfScalar(T, haystack, needle),
    }
}

/// Find the Index of a String (`needle`) within a Slice of Strings `haystack`. (Why is this not in std.mem?!?!? Did I miss it?)
/// (Borrowed from Cova. Make a Utils Library?)
pub fn indexOfEqlIgnoreCase(haystack: []const []const u8, needle: []const u8) ?usize {
    for (haystack, 0..) |hay, idx| if (ascii.eqlIgnoreCase(hay, needle)) return idx;
    return null;
}
