const std = @import("std");
const crypto = std.crypto;
const Shake128 = crypto.hash.sha3.CShake128;
const ff = std.crypto.ff;
const Allocator = std.mem.Allocator;

const KEY_LENGTH = 32;
const PRF_BYTES_PER_FE = 8;

const PRF_DOMAIN_SEP: [16]u8 = .{
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff,
    0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
};


/// **`FieldType`** is a type parameter that would represents any finite field .
/// - Output is an **array** of `FieldType.Element`.
/// - **No dynamic allocations**.
///
/// Example Usage:
/// const PRF = Pseudorandom(ff.secp256k1);
/// 
pub fn Pseudorandom(comptime FieldType: type, comptime OutputLength: usize) type {
    return struct {
        const Self = @This();

        pub const Key = [KEY_LENGTH]u8;
        pub const Output = [OutputLength]FieldType.Element;

        field: FieldType,

        pub fn init(field: FieldType) Self {
            return .{ .field = field };
        }

        pub fn gen(rng: *std.rand.Random) Key {
            var key: Key = undefined;
            rng.bytes(&key);
            return key;
        }

        pub fn apply(self: *const Self, key: *const Key, epoch: u32, index: u64) Output {
            var hasher = Shake128.init(.{});
            hasher.update(&PRF_DOMAIN_SEP);
            hasher.update(key);

            const epoch_bytes = std.mem.toBytes(epoch);
            hasher.update(&epoch_bytes);

            const index_bytes = std.mem.toBytes(index);
            hasher.update(&index_bytes);

            var prf_output: [PRF_BYTES_PER_FE * OutputLength]u8 = undefined;
            hasher.squeeze(&prf_output);

            var result: Output = undefined;
            for (0..OutputLength) |i| {
                const chunk = prf_output[i * PRF_BYTES_PER_FE .. (i + 1) * PRF_BYTES_PER_FE];
                result[i] = self.field.importLittleEndian(chunk) catch unreachable;
            }
            return result;
        }
    };
}

test "Pseudorandom output is deterministic" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    const field = try ff.secp256k1(allocator);

    // Define a PRF instance
    const PRF4 = Pseudorandom(@TypeOf(field), 4);
    var prf = PRF4.init(field);

    // Create a deterministic key
    var key: PRF4.Key = undefined;
    for (0..KEY_LENGTH) |i| {
        key[i] = @truncate(i % 256);
    }

    const epoch: u32 = 42;
    const index: u64 = 7;

    // Compute PRF output twice
    const out1 = prf.apply(&key, epoch, index);
    const out2 = prf.apply(&key, epoch, index);

    // Expect the outputs to be the same
    try std.testing.expectEqual(out1, out2);
}

test "Pseudorandom output changes when epoch changes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    // Choose a finite field (e.g., BLS12-381 scalar field)
    const field = try ff.bls12_381.scalarField(allocator);

    const PRF4 = Pseudorandom(@TypeOf(field), 4);
    var prf = PRF4.init(field);

    var key: PRF4.Key = undefined;
    for (0..KEY_LENGTH) |i| {
        key[i] = @truncate(i + 10);
    }

    const index: u64 = 7;
    const epoch1: u32 = 42;
    const epoch2: u32 = 43;

    const out1 = prf.apply(&key, epoch1, index);
    const out2 = prf.apply(&key, epoch2, index);

    // Ensure that different epochs give different outputs
    var changed = false;
    for (0..out1.len) |i| {
        if (!out1[i].eql(out2[i])) {
            changed = true;
            break;
        }
    }
    try std.testing.expect(changed);
}
