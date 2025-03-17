const std = @import("std");
const poseidon = @import("poseidon.zig");
const bn254 = @import("poseidon/bn254/fr.zig");

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

    /// Encode the tweak fields into BN254Fr elements.
    pub fn toFieldElements(self: PoseidonTweak) []bn254.Fr.MontgomeryDomainFieldElement {
        switch (self) {
            .tree => |t| {
                var out: [2]bn254.Fr.MontgomeryDomainFieldElement = undefined;

                out[0] = intToMont(t.level);
                out[1] = intToMont(t.pos_in_level);

                return out[0..2];
            },
            .chain => |c| {
                var out: [3]bn254.Fr.MontgomeryDomainFieldElement = undefined;

                out[0] = intToMont(u32, c.epoch);
                out[1] = intToMont(u32, @intCast(c.chain_index));
                out[2] = intToMont(u32, @as(u32, @intCast(c.pos_in_chain)));

                return out[0..3];
            },
        }
    }
};

fn intToMont(comptime T: type, value: T) bn254.Fr.MontgomeryDomainFieldElement {
    var buf: [32]u8 = .{0} ** 32;
    // Write as little-endian
    std.mem.writeInt(&buf, @intCast(value), .little);
    var tmp_non_mont: bn254.Fr.NonMontgomeryDomainFieldElement = .{0} ** 4;
    bn254.Fr.fromBytes(&tmp_non_mont, buf);
    var out: bn254.Fr.MontgomeryDomainFieldElement = .{0} ** 4;
    bn254.Fr.toMontgomery(&out, tmp_non_mont);
    return out;
}

/// each field is 32 bytes => fromBytes => toMontgomery.
fn bytesToFields(data: []const u8) ![]bn254.Fr.MontgomeryDomainFieldElement {
    const chunk_size = 32;
    const len_full_chunks = data.len / chunk_size;
    const remainder = data.len % chunk_size;

    var list = std.ArrayList(bn254.Fr.MontgomeryDomainFieldElement).init(std.heap.page_allocator);

    // full 32-byte chunks
    for (0..len_full_chunks) |i| {
        const start = i * chunk_size;
        var buf: [32]u8 = undefined;
        std.mem.copy(u8, buf[0..], data[start .. start + chunk_size]);
        var non_m: bn254.Fr.NonMontgomeryDomainFieldElement = .{0} ** 4;
        bn254.Fr.fromBytes(&non_m, buf);
        var mont: bn254.Fr.MontgomeryDomainFieldElement = .{0} ** 4;
        bn254.Fr.toMontgomery(&mont, non_m);
        try list.append(mont);
    }

    // handle remainder, if any
    if (remainder != 0) {
        var buf: [32]u8 = .{0} ** 32;
        std.mem.copy(u8, buf[0..remainder], data[len_full_chunks * chunk_size ..]);
        var non_m: bn254.Fr.NonMontgomeryDomainFieldElement = .{0} ** 4;
        bn254.Fr.fromBytes(&non_m, buf);
        var mont: bn254.Fr.MontgomeryDomainFieldElement = .{0} ** 4;
        bn254.Fr.toMontgomery(&mont, non_m);
        try list.append(mont);
    }

    return list.toOwnedSlice();
}

pub const PoseidonTweakHash = struct {
    const Self = @This();

    // The size in bytes of "parameter" or "output", if you want that
    parameter_size: usize,
    output_size: usize,

    pub fn init(parameter_size: usize, output_size: usize) Self {
        return .{ .parameter_size = parameter_size, .output_size = output_size };
    }

    /// Generate a random parameter of size `parameter_size`.
    pub fn rand_parameter(self: Self) []u8 {
        var buf: [1024]u8 = undefined; // if max param_size <= 1024
        const slice = buf[0..self.parameter_size];
        std.crypto.random.bytes(slice);
        return slice;
    }

    /// 1) Convert parameter => fields
    /// 2) Convert tweak => fields
    /// 3) Convert each message chunk => fields
    /// 4) Put them all in a single [w-1] array or multiple calls?
    ///    Actually your Poseidon code is designed to handle exactly w-1 inputs (for w≥2).
    ///    If you have more data, you might need a sponge approach or multiple calls.
    ///    For demonstration, let's do w=6 => 5 inputs. We'll combine everything into 5 fields.
    pub fn hash(
        self: Self,
        parameters_json: *const poseidon.parameters.PoseidonFamilyParameters(bn254.Fr),
        tweak: PoseidonTweak,
        param_data: []const u8,
        msg: []const u8,
    ) ![self.output_size]u8 {
        // 1) Construct the Poseidon instance with width.
        const w = 6;
        // get the BN254 config for width=6
        _ = parameters_json.get_params_for_width(@as(u8, @intCast(w)));
        var poseidon_instance = poseidon.Poseidon(bn254.Fr, w).init(parameters_json.*);

        // 2) Convert param_data => 1 or more fields
        const param_fields = try bytesToFields(param_data);

        // 3) Convert tweak => fields
        const tweak_fields = tweak.toFieldElements();

        // 4) Convert the entire msg => fields
        const msg_fields = try bytesToFields(msg);

        // try sponge late

        const total_needed = param_fields.len + tweak_fields.len + msg_fields.len;
        if (total_needed > (w - 1)) {
            return error.InputTooLarge;
        }

        var input_arr: [w - 1]bn254.Fr.MontgomeryDomainFieldElement = .{.{0} ** 4} ** (w - 1);
        var idx: usize = 0;

        // Copy param_fields
        for (param_fields) |f| {
            input_arr[idx] = f;
            idx += 1;
        }
        // Copy tweak_fields
        for (tweak_fields) |f| {
            input_arr[idx] = f;
            idx += 1;
        }
        // Copy msg_fields
        for (msg_fields) |f| {
            input_arr[idx] = f;
            idx += 1;
        }
        // If there's still leftover slots, they'd be zero

        const out_non_mont = poseidon_instance.hash(input_arr);

        // Convert that to bytes
        var out_bytes: [32]u8 = .{0};
        bn254.Fr.toBytes(&out_bytes, out_non_mont);

        // Return only the first `self.output_size` bytes
        var final_slice: [self.output_size]u8 = undefined;
        std.mem.copy(u8, final_slice[0..], out_bytes[0..self.output_size]);
        return final_slice;
    }
};

test "PoseidonTweakHash example" {
    // 1) Allocate PoseidonFamilyParameters for BN254
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer gpa.deinit();

    var baby_params = try poseidon.parameters.get_babyjubjub_parameters(allocator);
    defer baby_params.deinit();

    // 2) Instantiate a TweakHash
    var hasher = PoseidonTweakHash.init(16, 16);

    // 3) Generate a random parameter
    const param = hasher.rand_parameter();
    // 4) Make a sample tweak
    const tw = PoseidonTweak.tree{
        .level = 3,
        .pos_in_level = 777,
    };
    // 5) Some message
    const msg = "Hello Poseidon";
    // 6) Hash
    const digest = try hasher.hash(&baby_params, tw, param, msg);

    std.debug.print("Poseidon Tweak Hash digest = {x}\n", .{digest});
}
