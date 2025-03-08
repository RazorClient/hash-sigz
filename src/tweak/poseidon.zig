const std = @import("std");
const poseidon = @import("poseidon");


/// A tweak that can be either `.tree` or `.chain`.
pub const PoseidonTweak = union(enum) {
    tree: struct {
        level: u8,
        pos_in_level: u32,
    },
    chain: struct {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },

    /// Encode this tweak as a small array of Poseidon field elements.
    pub fn toFieldElements(self: PoseidonTweak) []Poseidon.FieldElement {
        switch (self) {
            .tree => |t| {
                var out: [2]Poseidon.FieldElement = .{
                    Poseidon.FieldElement.fromU8(t.level),
                    Poseidon.FieldElement.fromU32(t.pos_in_level),
                };
                return out[0..];
            },
            .chain => |c| {
                var out: [3]Poseidon.FieldElement = .{
                    Poseidon.FieldElement.fromU32(c.epoch),
                    Poseidon.FieldElement.fromU32(@intCast(u32, c.chain_index)),
                    Poseidon.FieldElement.fromU32(@intCast(u32, c.pos_in_chain)),
                };
                return out[0..];
            },
        }
    }
};


// pub fn tweakablePoseidonHash(input: []poseidon.FieldElement, tweak: []u8) !poseidon.FieldElement {
//     // Step 1: Encode the tweak into field elements
//     // var encodedTweak = try encodeTweak(tweak);

//     // Step 2: Combine the input with the encoded tweak
//     var combinedInput = std.array.concat(poseidon.FieldElement, input, encodedTweak);

//     // Step 3: Compute the Poseidon hash on the combined input
//     return poseidon.hash(combinedInput);
// }


/// Combine the tweak with the main input before hashing
fn prepareInputWithTweak(input: []poseidon.FieldElement, tweak: []poseidon.FieldElement, t: usize) ![]poseidon.FieldElement {
    var combined: []poseidon.FieldElement = try std.heap.page_allocator.alloc(poseidon.FieldElement, t);

    const input_len = input.len;
    const tweak_len = tweak.len;

    if (input_len + tweak_len > t) {
        return error.InputTooLarge; // Needs sponge mode
    }

    // Copy input elements
    std.mem.copy(poseidon.FieldElement, combined[0..input_len], input);

    // Copy tweak elements
    std.mem.copy(poseidon.FieldElement, combined[input_len..(input_len + tweak_len)], tweak);

    // Zero-pad if needed
    for (input_len + tweak_len..t) |i| {
        combined[i] = poseidon.FieldElement.zero();
    }

    return combined;
}

pub const PoseidonTweakHash = struct {
    const Self = @This();

    parameter_size: usize,
    output_size: usize,

    pub fn init(parameter_size: usize, output_size: usize) Self {
        return .{ .parameter_size = parameter_size, .output_size = output_size };
    }

    /// Absorb `parameter` + `tweak` + `msg` into Poseidon; return a (truncated) result.
    pub fn hash(
        self: Self,
        parameter: []const u8,
        tweak: PoseidonTweak,
        msg: []const []const u8,
    ) []u8 {
        var ps = Poseidon.init();

        // 1) Absorb parameter as field elements (could chunk it).
        for (parameter) |b| {
            Poseidon.absorb(&ps, Poseidon.FieldElement.fromU8(b));
        }

        // 2) Absorb the tweak as field elements
        const tweak_fes = tweak.toFieldElements();
        for (tweak_fes) |fe| {
            Poseidon.absorb(&ps, fe);
        }

        // 3) Absorb each message chunk
        //    Up to you how to chunk them into fields. Here again is a naive approach:
        for (msg) |m| {
            for (m) |b| {
                Poseidon.absorb(&ps, Poseidon.FieldElement.fromU8(b));
            }
        }

        // 4) Squeeze out a field element. If needed, do it multiple times 
        //    and gather them into the final output. Here we just do one:
        const fe_out = Poseidon.squeeze(&ps);

        // 5) Convert that field element to a byte array. For example, 32 bytes:
        var raw: [32]u8 = .{0};// or your actual field->bytes method
        // copy out up to self.output_size
        // e.g. pretend we wrote a fromFieldToBytes method:
        // fromFieldToBytes(fe_out, &raw);
        
        // Return the first `output_size` bytes
        return raw[0..self.output_size];
    }

    /// Example: generate random parameter of size `parameter_size`.
    pub fn rand_parameter(_: Self, parameter_size: comptime_int) []u8 {
        var buff: [parameter_size]u8 = undefined;
        std.crypto.random.bytes(&buff);
        return &buff;
    }

    pub fn tree_tweak(_: Self, level: u8, pos_in_level: u32) PoseidonTweak {
        return .{ .tree = .{ .level = level, .pos_in_level = pos_in_level } };
    }

    pub fn chain_tweak(_: Self, epoch: u32, chain_index: u16, pos_in_chain: u16) PoseidonTweak {
        return .{ .chain = .{ .epoch = epoch, .chain_index = chain_index, .pos_in_chain = pos_in_chain } };
    }
};