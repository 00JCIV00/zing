const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "zacket-lib",
        .root_source_file = .{ .path = "src/lib.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.install();

    // Add Library files as Modules
    std.debug.print("Adding Library Files as Modules...\n", .{});
    var src_dir = (std.fs.cwd()).openIterableDir("src/", .{}) catch return;
    defer src_dir.close();
    var src_dir_iter = src_dir.iterate();
    var mod_count: u16 = 0;
    while (src_dir_iter.next()) |next_file| {
        const file = next_file orelse break;
        if (!(file.kind == .File and std.mem.indexOf(u8, file.name, ".zig") == file.name.len - 4) or (std.mem.eql(u8, file.name, "lib.zig"))) continue;

        const mod_name = @constCast(&std.mem.tokenize(u8, file.name, ".")).peek() orelse {
            std.debug.print("There was an issue getting the module name of '{s}'.\n", .{ file.name });
            return;
        };
        const path = std.fmt.allocPrint(b.allocator, "src/{s}", .{ file.name }) catch |err| {
            std.debug.print("There was an issue making the relative path for '{s}':\n{}\n", .{ file.name, err });
            return;    
        };
        defer b.allocator.free(path);
        _ = b.addModule(mod_name, .{ .source_file = .{ .path = path } });
        std.debug.print("- Added > Module: {s}, File: {s}\n", .{ mod_name, path, });
        mod_count += 1;
    }
    else |err| { 
        std.debug.print("\nThere was an error while traversing the 'src' directory:\n{}\n", .{ err });
        return;
    }
    std.debug.print("Added {d} Library Files as Modules.\n", .{ mod_count });

    // Creates a step for unit testing.
    const main_test = b.addTest(.{
        .root_source_file = .{ .path = "src/test.zig" },
        .target = target,
        .optimize = optimize,
    });
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_test.step);

    const tested_install_step = b.step("tested-install", "Run library tests, then install.");
    tested_install_step.dependOn(@constCast(test_step));
    tested_install_step.dependOn(b.getInstallStep());

    b.default_step = @constCast(tested_install_step);
}
