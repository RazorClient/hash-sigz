const std = @import("std");
const rand = std.rand;

const PoseidonHash = @import("babybear").Poseidon2BabyBear;
const Field = @import("babybear").babybear;

// A constant for the length of the domain separator parameters.
pub const DOMAIN_PARAMETERS_LENGTH: usize = 4;

// These constants would be defined elsewhere.
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u64 = 0xAAAABBBB; // example constant
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u64 = 0xCCCCDDDD; // example constant


/// An enum to represent tweak values (for tree or chain use).  
/// For simplicity we assume that the combined tweak fits in a u64.
/// (A full implementation would use a big-integer library.)
pub const PoseidonTweak = union(enum) {
    TreeTweak: struct {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak: struct {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },

    /// Converts a tweak into field elements by first packing the tweak
    /// into a u64 (using bit shifts and adding a separator) and then
    /// decomposing it in base‑p.
    /// For demonstration we assume TWEAK_LEN is small and the u64 value
    /// suffices. In production you might use an arbitrary‑precision integer.
    pub fn toFieldElements(comptime TWEAK_LEN: usize, self: PoseidonTweak) []F {
        // Pack the tweak into a u64.
        var packed: u64 = 0;
        switch (self) {
            .TreeTweak => |t| {
                packed = (@as(u64, t.level) << 40)
                         + (@as(u64, t.pos_in_level) << 8)
                         + TWEAK_SEPARATOR_FOR_TREE_HASH;
            },
            .ChainTweak => |c| {
                packed = (@as(u64, c.epoch) << 40)
                         + ((@as(u64, c.chain_index)) << 24)
                         + ((@as(u64, c.pos_in_chain)) << 8)
                         + TWEAK_SEPARATOR_FOR_CHAIN_HASH;
            },
        }
        // Decompose 'packed' into TWEAK_LEN digits in base-p.
        // Here we assume that bn254.Fr provides a constant `p` (the modulus)
        // and a function `from_u64(u64) F`.
        var out: [TWEAK_LEN]F = undefined;
        var rem = packed;
        const P = bn254.Fr.modulus_u64(); // assume this returns a u64 modulus
        for (i, _) in out {
            // digit = rem mod P
            const digit = rem % P;
            out[i] = bn254.Fr.from_u64(digit);
            rem = rem / P;
        }
        return out[0..TWEAK_LEN];
    }
};



/// Pads an input vector of field elements with zeroes so that its length equals the
/// Poseidon state width (instance.get_t()), then applies the permutation.
fn poseidon_padded_permute(instance: *poseidon.Poseidon(F, anytype), input: []F) []F {
    // Ensure input length does not exceed the state width.
    std.debug.assert(input.len <= instance.get_t(), "Input too long");
    var padded = input.toOwnedSlice(instance.allocator());
    padded.resize(instance.get_t(), bn254.Fr.zero());
    return instance.permutation(padded);
}

/// Poseidon compression: computes Permute(input) + input, then truncates to OUT_LEN.
pub fn poseidon_compress(comptime OUT_LEN: usize, instance: *poseidon.Poseidon(F, anytype), input: []F) [OUT_LEN]F {
    std.debug.assert(input.len >= OUT_LEN, "Input length must be at least output length");
    const permuted = poseidon_padded_permute(instance, input);
    var out: [OUT_LEN]F = undefined;
    for (i, _) in out {
        out[i] = permuted[i] + input[i];
    }
    return out;
}

/// Constructs a domain separator by interpreting an array of usize as a big integer
/// (each treated as u32) and converting it into field elements.
pub fn poseidon_safe_domain_separator(comptime OUT_LEN: usize, instance: *poseidon.Poseidon(F, anytype), params: []const usize) [OUT_LEN]F {
    // For demonstration, we combine the params into one u64.
    // A full implementation might use arbitrary‑precision arithmetic.
    var domain: u64 = 0;
    for (params) |p| {
        domain = domain * (1 << 32) + (@intCast(u64, p));
    }
    // Decompose domain into field elements (assume the number fits in u64).
    var input: []F = std.heap.page_allocator.create(F, instance.get_t()) catch unreachable;
    defer std.heap.page_allocator.destroy(input);
    for (i, _) in input {
        const digit = domain % bn254.Fr.modulus_u64();
        input[i] = bn254.Fr.from_u64(digit);
        domain = domain / bn254.Fr.modulus_u64();
    }
    return poseidon_compress(OUT_LEN, instance, input);
}

/// A simple Poseidon sponge that absorbs input (after padding) and then squeezes output.
/// (For brevity, error handling and re-allocation are omitted.)
pub fn poseidon_sponge(comptime OUT_LEN: usize, instance: *poseidon.Poseidon(F, anytype), capacity_value: []F, input: []F) [OUT_LEN]F {
    std.debug.assert(capacity_value.len < instance.get_t(), "Capacity too large");
    const rate = instance.get_t() - capacity_value.len;
    // Pad input to a multiple of rate.
    var padded_input = input.toOwnedSlice(instance.allocator());
    const extra = (rate - (input.len % rate)) % rate;
    padded_input.resize(input.len + extra, bn254.Fr.zero());
    // Initialize state: rate zeroes concatenated with capacity.
    var state: []F = std.heap.page_allocator.create(F, instance.get_t()) catch unreachable;
    defer std.heap.page_allocator.destroy(state);
    for (i, _) in state {
        if (i < rate) {
            state[i] = bn254.Fr.zero();
        } else {
            state[i] = capacity_value[i - rate];
        }
    }
    // Absorb phase.
    for (chunk) in padded_input.chunks(rate) {
        for (i, val) in chunk {
            state[i] = state[i] + val;
        }
        state = instance.permutation(state);
    }
    // Squeeze phase.
    var out: []F = std.heap.page_allocator.create(F, 0) catch unreachable;
    defer std.heap.page_allocator.destroy(out);
    while (out.len < OUT_LEN) {
        out.appendSlice(state[0..rate]) catch unreachable;
        state = instance.permutation(state);
    }
    // Truncate output.
    return out[0..OUT_LEN].toOwnedSlice(instance.allocator()).toOwnedArray();
}

///////////////////////////////////////////////////////////////////////////////
// PoseidonTweakHash
///////////////////////////////////////////////////////////////////////////////

/// A tweakable hash function implemented using Poseidon2.
/// All lengths are specified in number of field elements.
/// 
/// The compile-time parameters are:
/// - LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE: for tweak encoding
/// - PARAMETER_LEN: number of field elements for the public parameter
/// - HASH_LEN: number of field elements in the raw hash output
/// - TWEAK_LEN: number of field elements to encode the tweak
/// - CAPACITY: capacity used in the sponge mode
/// - NUM_CHUNKS: used for decoding (not shown here)
pub const PoseidonTweakHash = struct(
    comptime LOG_LIFETIME: usize,
    comptime CEIL_LOG_NUM_CHAINS: usize,
    comptime CHUNK_SIZE: usize,
    comptime PARAMETER_LEN: usize,
    comptime HASH_LEN: usize,
    comptime TWEAK_LEN: usize,
    comptime CAPACITY: usize,
    comptime NUM_CHUNKS: usize,
) {
    /// In this example, Parameter is an array of FIELD elements.
    pub const Parameter = [PARAMETER_LEN]F;
    pub const Domain = [HASH_LEN]F;
    pub const Tweak = PoseidonTweak;

    /// Generates a random Parameter.
    pub fn rand_parameter() Parameter {
        var par: Parameter = undefined;
        // For demonstration we simply use F.from_u64(1) as a placeholder.
        for (par) |*elem| {
            elem.* = bn254.Fr.rand(); // Assume bn254.Fr.rand() exists.
        }
        return par;
    }

    /// Generates a random Domain element.
    pub fn rand_domain() Domain {
        var dom: Domain = undefined;
        for (dom) |*elem| {
            elem.* = bn254.Fr.rand();
        }
        return dom;
    }

    /// Constructs a tree tweak.
    pub fn tree_tweak(level: u8, pos_in_level: u32) Tweak {
        return Tweak.TreeTweak{ .level = level, .pos_in_level = pos_in_level };
    }

    /// Constructs a chain tweak.
    pub fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) Tweak {
        return Tweak.ChainTweak{
            .epoch = epoch,
            .chain_index = chain_index,
            .pos_in_chain = pos_in_chain,
        };
    }

    /// Applies the tweakable hash.
    /// The `message` parameter is an array of Domain elements.
    pub fn apply(parameter: *const Parameter, tweak: Tweak, message: []const Domain) Domain {
        const l = message.len;
        // Create Poseidon instances. Here we assume two sets of parameters
        // (e.g. for different widths) are available as constants.
        var instance = poseidon.Poseidon(F, .{ .params = POSEIDON2_BABYBEAR_24_PARAMS });
        var instance_short = poseidon.Poseidon(F, .{ .params = POSEIDON2_BABYBEAR_16_PARAMS });

        if (l == 1) {
            // Compression mode: parameter || tweak || message[0]
            const tweak_fe = Tweak.toFieldElements(TWEAK_LEN, tweak);
            var combined: []F = std.array.concat(F, .{ parameter.*, tweak_fe, message[0] });
            return poseidon_compress(HASH_LEN, &instance_short, combined);
        } else if (l == 2) {
            // Compression mode with two message parts.
            const tweak_fe = Tweak.toFieldElements(TWEAK_LEN, tweak);
            var combined: []F = std.array.concat(F, .{ parameter.*, tweak_fe, message[0], message[1] });
            return poseidon_compress(HASH_LEN, &instance, combined);
        } else if (l > 2) {
            // Use sponge mode.
            const tweak_fe = Tweak.toFieldElements(TWEAK_LEN, tweak);
            var combined: []F = std.array.concat(F, .{ parameter.*, tweak_fe });
            // Flatten the array of Domain messages.
            for (message) |sub_arr| {
                combined.appendSlice(sub_arr) catch {};
            }
            const lengths: [DOMAIN_PARAMETERS_LENGTH]usize = .{ PARAMETER_LEN, TWEAK_LEN, NUM_CHUNKS, HASH_LEN };
            const safe_input = poseidon_safe_domain_separator(CAPACITY, &instance, lengths);
            return poseidon_sponge(HASH_LEN, &instance, safe_input, combined);
        }
        // Fallback (should not be reached)
        return undefined; // or return an array filled with F.one()
    }

    /// For testing purposes: verifies internal consistency.
    pub fn internal_consistency_check() void {
        std.debug.assert(CAPACITY < 24, "Capacity must be less than 24");
        std.debug.assert(PARAMETER_LEN + TWEAK_LEN + HASH_LEN <= 16, "Input too large for instance");
        std.debug.assert(PARAMETER_LEN + TWEAK_LEN + 2 * HASH_LEN <= 24, "Input too large for tree instance");
        // Additional checks on bit-lengths may be added.
    }
};

///////////////////////////////////////////////////////////////////////////////
// Example Instantiations
///////////////////////////////////////////////////////////////////////////////

/// An instantiation with specific parameters.
pub const PoseidonTweak44 = PoseidonTweakHash(20, 8, 2, 4, 4, 3, 9, 128);
pub const PoseidonTweak37 = PoseidonTweakHash(20, 8, 2, 3, 7, 3, 9, 128);
pub const PoseidonTweakW1L18 = PoseidonTweakHash(18, 8, 1, 5, 7, 2, 9, 163);
pub const PoseidonTweakW1L5 = PoseidonTweakHash(5, 8, 1, 5, 7, 2, 9, 163);


test "PoseidonTweakHash apply tests" {
    // For randomness, one might use std.rand.DefaultPrng.
    var prng = rand.DefaultPrng.init(0);
    // Test with PoseidonTweak44.
    PoseidonTweak44.internal_consistency_check();
    // Generate a random parameter.
    var parameter = PoseidonTweak44.rand_parameter();
    // Generate one or two random Domain elements.
    var message_one = PoseidonTweak44.rand_domain();
    var message_two = PoseidonTweak44.rand_domain();
    const tweak_tree = PoseidonTweak44.tree_tweak(0, 3);
    _ = PoseidonTweak44.apply(&parameter, tweak_tree, &[_]PoseidonTweak44.Domain{ message_one, message_two });

    var parameter2 = PoseidonTweak44.rand_parameter();
    var msg_one = PoseidonTweak44.rand_domain();
    const tweak_chain = PoseidonTweak44.chain_tweak(2, 3, 4);
    _ = PoseidonTweak44.apply(&parameter2, tweak_chain, &[_]PoseidonTweak44.Domain{ msg_one });

    var parameter3 = PoseidonTweak44.rand_parameter();
    var chains: [128]PoseidonTweak44.Domain = undefined;
    for (chains) |*elem| {
        elem.* = PoseidonTweak44.rand_domain();
    }
    const tweak_tree2 = PoseidonTweak44.tree_tweak(0, 3);
    _ = PoseidonTweak44.apply(&parameter3, tweak_tree2, &chains);
}
