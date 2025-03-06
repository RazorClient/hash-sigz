const std = @import("std");
//todo:fix this lib issue
const poseidon = @import("poseidon");

// lib problems fix later layout what ill do 
pub const PoseidonTweakHash = struct {
    /// Example parameters 
    capacity: usize,
    rate: usize,
    field_bits: usize, // e.g. 31-bit prime, 64-bit prime, etc.
    output_elements: usize, // how many field elements you want in the output

    /// Creates a new PoseidonTweakHash with given parameters.
    pub fn init(
        capacity: usize,
        rate: usize,
        field_bits: usize,
        output_elements: usize,
    ) PoseidonTweakHash {
        return .{
            .capacity = capacity,
            .rate = rate,
            .field_bits = field_bits,
            .output_elements = output_elements,
        };
    }

    /// Hash in "compression mode"
    pub fn hash(
        self: *PoseidonTweakHash,
        parameter: []const u8,
        tweak: PoseidonTweak,
        msg_list: [][]const u8,
        allocator: *std.mem.Allocator,
    ) ![]u8 {
        // 1. Convert parameter, tweak, messages into field elements or store them as bytes to be absorbed.
        const tweak_bytes = tweak.toBytes();
        
        // In a real implementation, you'd do:
        //   - break parameter, tweak_bytes, and msg bytes into field-element blocks
        //   - perform the appropriate Poseidon permutation calls (compression or sponge).
        // For demonstration, we'll do a naive "combine and call PoseidonPermutation(...)".

        // 2. Combine all input data:
        var combined_length = parameter.len + tweak_bytes.len;
        for (msg_list) |m| {
            combined_length += m.len;
        }

        var combined = try allocator.alloc(u8, combined_length);
        defer allocator.free(combined);

        var cursor: usize = 0;
        std.mem.copy(u8, combined[cursor..cursor+parameter.len], parameter);
        cursor += parameter.len;
        std.mem.copy(u8, combined[cursor..cursor+tweak_bytes.len], tweak_bytes);
        cursor += tweak_bytes.len;

        for (msg_list) |m| {
            std.mem.copy(u8, combined[cursor..cursor+m.len], m);
            cursor += m.len;
        }

        // 3. Convert 'combined' into field elements or pass to your PoseidonPermutation.
        //    Let's pretend we have a function "poseidonCompress" that does the job.

        const out_field = try poseidonCompress(combined, self.capacity, self.rate, self.field_bits, self.output_elements, allocator);

        // 4. Convert field-element output to bytes if needed, then return.
        //    In many zero-knowledge settings, you might just keep them as field elements.

        // We'll assume poseidonCompress returns a slice of field elements. 
        // We'll flatten them into a byte array for the final output.

        // In real code, you might do something like:
        // var out_bytes = try fieldElementsToBytes(out_field, self.field_bits, allocator);
        // return out_bytes;
        return out_field;
    }
};

/// A stub for the actual Poseidon-based compression. 
/// Real code would apply the Poseidon permutation + capacity/rate logic.
/// 
/// In practice, you:
///   1) Parse `data` into field elements
///   2) Absorb them (and possibly do domain separation) 
///   3) Run the Poseidon permutation
///   4) Return the first `output_elements` as the compression output
fn poseidonCompress(
    data: []const u8,
    capacity: usize,
    rate: usize,
    field_bits: usize,
    output_elements: usize,
    allocator: *std.mem.Allocator,
) ![]u8 {
    // Stub logic: you would convert the data into field elements 
    // using e.g. "base-2^field_bits" or your chosen prime modulus. 
    // Then run the Poseidon permutation.
    // For demonstration, we'll just "pretend" and return data truncated to some length.

    const output_len = output_elements * (field_bits / 8); // e.g. if field_bits=256, output_elements=1 => 32 bytes
    const out = try allocator.alloc(u8, output_len);
    // In real code: fill `out` with the real Poseidon result.
    // For now, let's just copy some subset of the input:
    if (data.len < output_len) {
        // if input smaller than needed, repeat or something else
        std.mem.copy(u8, out, data);
    } else {
        std.mem.copy(u8, out, data[0..output_len]);
    }
    return out;
}
