const std = @import("std");
const crypto = std.crypto;
const Shake128 = crypto.hash.sha3.CShake128;
const Allocator = std.mem.Allocator;

const KEY_LENGTH = 32;
const PRF_BYTES_PER_FE = 8;

const PRF_DOMAIN_SEP: [16]u8 = .{
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff,
    0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
};

// Placeholder for the field representation
// try zomething else later
pub const Ff = struct {
    pub const MODULUS: u64 = 0x1fffffff; // just a trial

    pub fn from(value: u64) Ff {
        return Ff{ .value = value % MODULUS };
    }

    value: u64,
};

//hacky fix
fn bigUintMod(bytes: []const u8, modulus: u64) u64 {
    const chunk_len = @min(bytes.len, 8);
    var val: u64 = 0;
    for (0..chunk_len) |i| {
        const shift_amount: u6 = @intCast((@as(u64, i) % 128) * 8);
        val |= (@as(u64, bytes[i]) << shift_amount);
    }
    return val % modulus;
}

fn eqFp(a: Ff, b: Ff) bool {
    return a.value == b.value;
}

/// Returns true if two arrays of field elements are equal.
fn eqFpArray(comptime N: usize, a: [N]Ff, b: [N]Ff) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |elem, i| { // ✅ Correctly capture `i`
        if (!eqFp(elem, b[i])) return false;
    }
    return true;
}

pub fn Pseudorandom(comptime OutputLength: usize) type {
    return struct {
        const Self = @This();

        pub const Key = [KEY_LENGTH]u8;
        pub const Output = [OutputLength]Ff;

        /// Generate a new random key using a given RNG.
        pub fn gen(rng: *std.rand.Random) Key {
            var key: Key = undefined;
            rng.bytes(&key);
            return key;
        }

        /// Apply the pseudorandom function with the given key, epoch, and index.
        pub fn apply(key: *const Key, epoch: u32, index: u64) Output {
            var hasher = Shake128.init(.{});

            // Hash the domain separator
            hasher.update(&PRF_DOMAIN_SEP);

            // Hash the key
            hasher.update(key);

            // Hash the epoch
            var epoch_bytes = std.mem.toBytes(epoch);
            hasher.update(&epoch_bytes);

            // Hash the index
            var index_bytes = std.mem.toBytes(index);
            hasher.update(&index_bytes);

            // Finalize SHAKE128 and extract bytes
            var prf_output: [PRF_BYTES_PER_FE * OutputLength]u8 = undefined;
            hasher.squeeze(&prf_output);

            var result: Output = undefined;

            // Convert bytes to field elements
            for (0..OutputLength) |i| {
                const chunk = prf_output[i * PRF_BYTES_PER_FE .. (i + 1) * PRF_BYTES_PER_FE];
                const integer_value = bigUintMod(chunk, Ff.MODULUS);
                result[i] = Ff.from(integer_value);
            }

            return result;
        }
    };
}

test "Pseudorandom output is deterministic" {
    // Use Pseudorandom with 4 field elements.
    const PRF4 = Pseudorandom(4);
    var key: PRF4.Key = undefined;
    // Initialize key with a predictable pattern.
    for (0..KEY_LENGTH) |i| {
        key[i] = @truncate(i % 256); // Ensures that i stays within u8 range (0-255)

    }
    const epoch: u32 = 42;
    const index: u64 = 7;

    const out1 = PRF4.apply(&key, epoch, index);
    const out2 = PRF4.apply(&key, epoch, index);

    // Expect the outputs to be equal.
    try std.testing.expect(eqFpArray(4, out1, out2));
}

test "Pseudorandom output changes when epoch changes" {
    const PRF4 = Pseudorandom(4);
    var key: PRF4.Key = undefined;
    // Fixed key with a simple pattern.
    for (0..KEY_LENGTH) |i| {
        key[i] = @truncate(i + 10);
    }
    const index: u64 = 7;
    const epoch1: u32 = 42;
    const epoch2: u32 = 43;

    const out1 = PRF4.apply(&key, epoch1, index);
    const out2 = PRF4.apply(&key, epoch2, index);

    // Expect outputs to differ if the epoch changes.
    try std.testing.expect(!eqFpArray(4, out1, out2));
}

test "Pseudorandom key generation returns 32 bytes" {
    const PRF4 = Pseudorandom(4);
    // Use a deterministic pseudo-random generator.
    const seed: u64 = 12345678; // Replace with actual randomness if needed
    var prng = std.rand.DefaultPrng.init(seed);
    var rng = prng.random(); // Get the RNG instance

    const key = PRF4.gen(&rng);
    try std.testing.expect(key.len == KEY_LENGTH);
}
