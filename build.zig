const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library
    const paseto = b.addStaticLibrary(.{
        .name = "paseto",
        .root_source_file = b.path("src/paseto.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(paseto);

    // Module for other projects
    const paseto_module = b.addModule("paseto", .{
        .root_source_file = b.path("src/paseto.zig"),
    });

    // Tests
    const lib_tests = b.addTest(.{
        .root_source_file = b.path("src/paseto.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);

    // Example executable
    const example = b.addExecutable(.{
        .name = "paseto-example",
        .root_source_file = b.path("examples/basic.zig"),
        .target = target,
        .optimize = optimize,
    });
    example.root_module.addImport("paseto", paseto_module);
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example", "Run the example");
    example_step.dependOn(&run_example.step);
}