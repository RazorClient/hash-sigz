const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;
const random = std.crypto.random;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

const TWEAK_SEPARATOR_MESSAGE: u8 = 0x02;
/// Default digest length for Poseidon in this example (32 bytes, or 256 bits).
const POSEIDON_DIGEST_LENGTH = 32;

/// This structure manages the “message hash” logic with Poseidon:
/// - A random parameter (to randomize hashing)
/// - The size of randomness
/// - The chunk size for splitting final output
pub const PoseidonMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    chunk_size: usize,
    parameter: []u8,

    /// Initialize by allocating a random parameter of `parameter_size` bytes.
    pub fn init(
        allocator: std.mem.Allocator,
        parameter_size: usize,
        randomness_size: usize,
        chunk_size: usize,
    ) !Self {
        const parameter = try allocator.alloc(u8, parameter_size);
        random.bytes(parameter);
        return Self{
            .parameter_size = parameter_size,
            .randomness_size = randomness_size,
            .chunk_size = chunk_size,
            .parameter = parameter,
        };
    }

    /// Clean up the allocated parameter when done.
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.parameter);
    }

    /// Generate randomness of size `randomness_size`.
    pub fn generateRandomness(self: *const Self) []u8 {
        return random.bytes(self.randomness_size);
    }

    /// Absorb the randomness, parameter, epoch, a tweak separator, and the message
    /// into a Poseidon state. Finally, squeeze out a digest and split it into chunks.
    pub fn apply(
        self: *const Self,
        allocator: std.mem.Allocator,
        epoch: u32,
        randomness: []const u8,
        message: []const u8,
    ) ![]u8 {
        // 1) Initialize Poseidon state.
        var state = Poseidon.init();

        // 2) Absorb the randomness bytes as field elements.
        for (randomness) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 3) Absorb the parameter bytes as field elements.
        for (self.parameter) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 4) Absorb the epoch as four bytes (big-endian).
        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        for (epoch_bytes) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 5) Absorb the tweak separator for a message.
        Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(TWEAK_SEPARATOR_MESSAGE));

        // 6) Absorb the message bytes.
        for (message) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 7) Squeeze out one field element for the final digest.
        const fe_out = Poseidon.squeeze(&state);

        // 8) Convert the field element to a fixed-length byte array.
        var digest: [POSEIDON_DIGEST_LENGTH]u8 = undefined;
        Poseidon.fieldElementToBytes(fe_out, &digest);

        // 9) Optionally split the digest into chunks of `chunk_size` bytes and return.
        return bytesToChunks(allocator, &digest, self.chunk_size);
    }
};

test "PoseidonMessageHash basic test" {
    // We’ll use an ArenaAllocator to easily free everything at the end.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    // We pick some test parameters
    const param_size = 32; // Example: 32 bytes of parameter
    const randomness_size = 16; // Example: 16 bytes of randomness
    const chunk_size = 8; // Example: 8 bytes per chunk

    // Initialize the PoseidonMessageHash instance
    var pmh = try PoseidonMessageHash.init(alloc, param_size, randomness_size, chunk_size);
    defer pmh.deinit(alloc);

    // Generate randomness
    const rand_bytes = pmh.generateRandomness();
    try testing.expectEqual(@as(usize, randomness_size), rand_bytes.len);

    // Prepare a sample message
    const message = "Hello from Poseidon!";

    // Apply the Poseidon-based hash with a sample epoch
    const epoch: u32 = 42;
    const digest_chunks = try pmh.apply(alloc, epoch, rand_bytes, message);
    defer alloc.free(digest_chunks);

    // Check that the total output length is as expected.
    // If we set chunk_size=8 and the default digest length=32 bytes,
    // we typically get 4 chunks => total length = 4 * 8 = 32.
    try testing.expectEqual(@as(usize, 32), digest_chunks.len);

    // TODO: add more checks if you have reference data or want to verify
    // actual content. For now, we just verify chunking logic.
}

test "PoseidonMessageHash empty message test" {
    // Test absorbing an empty message
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    // Reuse the same initial parameters as above
    const param_size = 32;
    const randomness_size = 16;
    const chunk_size = 8;

    var pmh = try PoseidonMessageHash.init(alloc, param_size, randomness_size, chunk_size);
    defer pmh.deinit(alloc);

    const rand_bytes = pmh.generateRandomness();
    const empty_message: []const u8 = &.{};

    const digest_chunks = try pmh.apply(alloc, 1337, rand_bytes, empty_message);
    defer alloc.free(digest_chunks);

    //  check, confirm the final length
    try testing.expectEqual(@as(usize, 32), digest_chunks.len);

    // TODO: check the actual bytes once Poseidon is fully implemented
}
