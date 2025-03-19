const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add dependency
    const poseidon_pkg = b.dependency("poseidon", .{
        .target = target,
        .optimize = optimize,
    });
    // const poseidon = poseidon_pkg.module("poseidon");
    const babybear = poseidon_pkg.module("poseidon-babybear");

    // Add main module
    const mod = b.addModule("hash-sigz", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "poseidon", .module = babybear },
        },
    });
    _ = mod;

    // Create static library
    const lib = b.addStaticLibrary(.{
        .name = "hash-sigz",
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = optimize,
        .target = target,
    });
    lib.root_module.addImport("babybear", babybear);
    // lib.root_module.addImport("poseidon", poseidon);
    b.installArtifact(lib);

    // Unit tests
    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .optimize = optimize,
        .target = target,
    });
    // tests.root_module.addImport("poseidon", poseidon);
    tests.root_module.addImport("babybear", babybear);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
