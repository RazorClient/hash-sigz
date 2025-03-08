const std = @import("std");
const crypto = std.crypto;
const Shake128 = crypto.hash.sha3.CShake128;
const random = std.crypto.random;
const bytesToChunks = @import("../utils.zig").bytesToChunks;

const TWEAK_SEPERATOR_MESSAGE: u8 = 0x02;
const POSEIDON_DIGEST_LENGTH = 32;


pub const PoseidonMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    chunk_size: usize,
    parameter: []u8,

    /// Initialize by allocating a random parameter of `parameter_size` bytes.
    pub fn init(allocator: std.mem.Allocator, parameter_size: usize, randomness_size: usize, chunk_size: usize) !Self {
        const parameter = try allocator.alloc(u8, parameter_size);
        random.bytes(parameter);
        return Self{
            .parameter_size = parameter_size,
            .randomness_size = randomness_size,
            .chunk_size = chunk_size,
            .parameter = parameter,
        };
    }

    /// Free the allocated parameter.
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.parameter);
    }

    /// Generate randomness of size `randomness_size`.
    pub fn generateRandomness(self: *const Self) []u8 {
        return random.bytes(self.randomness_size);
    }

    /// Absorb the randomness, parameter, epoch, a tweak separator and the message
    /// into a Poseidon state, then squeeze out a digest and split it into chunks.
    pub fn apply(self: *const Self, allocator: std.mem.Allocator, epoch: u32, randomness: []const u8, message: []const u8) ![]u8 {
        var state = Poseidon.init();

        // 1) Absorb randomness: convert each byte into a field element.
        for (randomness) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 2) Absorb the parameter.
        for (self.parameter) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 3) Absorb the epoch.
        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        for (epoch_bytes) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 4) Absorb the tweak separator for a message.
        Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(TWEAK_SEPERATOR_MESSAGE));

        // 5) Absorb the message.
        for (message) |b| {
            Poseidon.absorb(&state, Poseidon.FieldElement.fromU8(b));
        }

        // 6) Squeeze out a field element digest.
        const fe_out = Poseidon.squeeze(&state);

        // 7) Convert the field element to bytes.
        var digest: [POSEIDON_DIGEST_LENGTH]u8 = undefined;
        Poseidon.fieldElementToBytes(fe_out, &digest);

        // 8) Split the digest into chunks as needed.
        return bytesToChunks(allocator, &digest, self.chunk_size);
    }
};
