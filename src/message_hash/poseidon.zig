const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;
const random = std.crypto.random;

const PoseidonHash = @import("babybear").Poseidon2BabyBear;
const Field = @import("babybear").babybear;

const MESSAGE_LENGTH = 32;
const TWEAK_SEPARATOR_MESSAGE: u8 = 0x02;
const POSEIDON_DIGEST_LENGTH = 32;
const mod = Field.PrimeModulus;

/// Encode a message into field elements
pub fn encodeMessage(comptime MSG_LEN_FE: usize, message: []const u8) [MSG_LEN_FE]Field {
    // 1) Convert the message bytes into a BigInt.
    var message_uint = std.math.big.int.BigInt.init(@sizeOf(u8) * message.len);
    _ = message_uint.setBytes(message, .little);

    // repeatedly do mod by Field.MODULUS to get each field element,then do a floor-division by the modulus
    var message_fe: [MSG_LEN_FE]Field = undefined;
    var i: usize = 0;

    while (i < MSG_LEN_FE) : (i += 1) {
        var tmp = message_uint;
        // remainder = message_uint mod p
        tmp.modAssign(mod, .little);
        // convert remainder into a field element
        message_fe[i] = Field.fromBytes(tmp.toBytesLe());
        // now message_uint = floor(message_uint / p)
        message_uint.divFloorAssign(Field.MODULUS, .little);
    }

    return message_fe;
}
/// Encode an epoch (tweak) as an array of TWEAK_LEN_FE field elements.
pub fn encodeEpoch(comptime TWEAK_LEN_FE: usize, epoch: u32) [TWEAK_LEN_FE]Field {
    // Allocate a BigInt for 5 bytes (epoch: 4 bytes, plus 1 separator byte)
    var epoch_uint = std.math.big.int.BigInt.init(5);
    var epoch_bytes: [5]u8 = [_]u8{
        @as(u8, epoch >> 24),
        @as(u8, epoch >> 16),
        @as(u8, epoch >> 8),
        @as(u8, epoch),
        TWEAK_SEPARATOR_MESSAGE,
    };
    // Set the BigInt bytes in big-endian order.
    _ = epoch_uint.setBytes(epoch_bytes[0..], .big);

    // Prepare the result array.
    var result: [TWEAK_LEN_FE]Field = undefined;
    var i: usize = 0;
    while (i < TWEAK_LEN_FE) : (i += 1) {
        // Compute remainder = epoch_uint mod Field.MODULUS
        var tmp = epoch_uint;
        tmp.modAssign(Field.PrimeModulus, .little);
        // Convert the remainder to a field element.
        result[i] = Field.fromBytes(tmp.toBytesLe());
        // Reduce epoch_uint for the next field element.
        epoch_uint.divFloorAssign(Field.MODULUS, .little);
    }
    return result;
}
/// Decode an array of HASH_LEN_FE field elements into NUM_CHUNKS many chunks,
/// where each chunk is an integer in [0, 2^(CHUNK_SIZE) - 1].
pub fn decodeToChunks(comptime NUM_CHUNKS: usize, comptime CHUNK_SIZE: usize, comptime HASH_LEN_FE: usize, field_elements: [HASH_LEN_FE]Field) ![]u8 {
    // 1) Combine field elements into one BigInt.
    var hash_uint = std.math.big.int.BigInt.init(0);
    // Convert Field.MODULUS (assumed to be a u32) to a BigInt.
    const modulus_bi = std.math.big.int.BigInt.fromUnsigned(@as(u64, Field.MODULUS));
    for (field_elements) |fe| {
        hash_uint.mulAssign(modulus_bi);
        // Convert the field element (in normal form) to a BigInt.
        const fe_bi = std.math.big.int.BigInt.fromUnsigned(@as(u64, Field.toNormal(fe)));
        hash_uint.addAssign(fe_bi);
    }

    // 2) Determine maximum chunk value: 2^(CHUNK_SIZE).
    // Zig's shift operator requires a shift count of a small integer type (conceptually 5 bits),
    // so we cast the shift amount with @intCast.
    const max_chunk_len = (@as(u16, 1) << @intCast(CHUNK_SIZE));

    // 3) Allocate an output buffer for NUM_CHUNKS chunks.
    var output = try std.heap.page_allocator.alloc(u8, NUM_CHUNKS);

    var i: usize = 0;
    while (i < NUM_CHUNKS) : (i += 1) {
        var chunk = hash_uint.clone();
        // Compute remainder: chunk = hash_uint mod max_chunk_len.
        chunk.modAssign(std.math.big.int.BigInt.fromInt(@as(i64, max_chunk_len)), .little);
        // Assume the remainder fits in one byte (valid if CHUNK_SIZE <= 8).
        output[i] = chunk.toBytesLe()[0];
        // Update hash_uint by dividing out the chunk.
        hash_uint.divFloorAssign(std.math.big.int.BigInt.fromInt(@as(i64, max_chunk_len)), .little);
    }
    return output;
}

pub const PoseidonMessageHash = struct {
    const Self = @This();

    parameter_size: usize,
    randomness_size: usize,
    chunk_size: usize,
    parameter: []u8,

    /// Initialize PoseidonMessageHash with a random parameter
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

    /// Free allocated memory
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.parameter);
    }

    /// Generate random bytes for randomness
    pub fn generateRandomness(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const rand_buf = try allocator.alloc(u8, self.randomness_size);
        random.bytes(rand_buf);
        return rand_buf;
    }

    /// Apply Poseidon message hash
    pub fn apply(
        self: *const Self,
        allocator: std.mem.Allocator,
        epoch: u32,
        randomness: []const u8,
        message: []const u8,
    ) ![]u8 {
        var state = Poseidon.init(); // TODO: Ensure Poseidon supports `init()`

        for (randomness) |b| {
            Poseidon.absorb(&state, Field.fromU8(b));
        }

        for (self.parameter) |b| {
            Poseidon.absorb(&state, Field.fromU8(b));
        }

        var epoch_fe = encodeEpoch(epoch);
        for (epoch_fe) |fe| {
            Poseidon.absorb(&state, fe);
        }

        Poseidon.absorb(&state, Field.fromU8(TWEAK_SEPARATOR_MESSAGE));

        var message_fe = encodeMessage(message);
        for (message_fe) |fe| {
            Poseidon.absorb(&state, fe);
        }

        const fe_out = Poseidon.squeeze(&state);

        var digest: [POSEIDON_DIGEST_LENGTH]u8 = undefined;
        Poseidon.fieldElementToBytes(fe_out, &digest);

        return decodeToChunks(&digest, self.chunk_size);
    }
};

// test "PoseidonMessageHash basic test" {
//     var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
//     defer arena_state.deinit();
//     const alloc = arena_state.allocator();

//     const param_size = 32;
//     const randomness_size = 16;
//     const chunk_size = 8;

//     var pmh = try PoseidonMessageHash.init(alloc, param_size, randomness_size, chunk_size);
//     defer pmh.deinit(alloc);

//     const rand_bytes = try pmh.generateRandomness(alloc);
//     defer alloc.free(rand_bytes);

//     const message = "Hello from Poseidon!";
//     const epoch: u32 = 42;
//     const digest_chunks = try pmh.apply(alloc, epoch, rand_bytes, message);
//     defer alloc.free(digest_chunks);

//     try testing.expectEqual(@as(usize, 32), digest_chunks.len);
// }

// test "PoseidonMessageHash empty message test" {
//     var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
//     defer arena_state.deinit();
//     const alloc = arena_state.allocator();

//     const param_size = 32;
//     const randomness_size = 16;
//     const chunk_size = 8;

//     var pmh = try PoseidonMessageHash.init(alloc, param_size, randomness_size, chunk_size);
//     defer pmh.deinit(alloc);

//     const rand_bytes = try pmh.generateRandomness(alloc);
//     defer alloc.free(rand_bytes);

//     const empty_message: []const u8 = &.{};

//     const digest_chunks = try pmh.apply(alloc, 1337, rand_bytes, empty_message);
//     defer alloc.free(digest_chunks);

//     try testing.expectEqual(@as(usize, 32), digest_chunks.len);
// }
