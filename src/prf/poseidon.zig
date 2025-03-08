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
pub fn PosiedonPRF(comptime FieldType: type, comptime OutputLength: usize) type {
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

        pub fn apply(self: *const Self, key: *const Key, epoch: u32, index: u64) !Output {
            var hasher = Shake128.init(.{});
            hasher.update(&PRF_DOMAIN_SEP);
            hasher.update(key);

            const epoch_bytes = std.mem.toBytes(epoch);
            hasher.update(&epoch_bytes);

            const index_bytes = std.mem.toBytes(index);
            hasher.update(&index_bytes);

            var prf_output: [PRF_BYTES_PER_FE * OutputLength]u8 = undefined;
            hasher.squeeze(&prf_output);
            // TODO: fix this part does out code depend upon ff in std or custom impl?
            var result: Output = undefined;
            for (0..OutputLength) |i| {
                const chunk = prf_output[i * PRF_BYTES_PER_FE .. (i + 1) * PRF_BYTES_PER_FE];
                const val_u64 = std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(chunk)), .little);
                result[i] = try FieldType.Element.fromPrimitive(u64, self.field.modulus, val_u64);

            
            }
            return result;
        }
    };
}

const dummyFf = struct {
    pub const MOD_BITS = 64;
    pub const Mod = ff.Modulus(MOD_BITS);
    pub const Element = Mod.Fe;

    // Here we use 0xffffffffffffffc5 (just as a simple odd number).
    pub const PRIME = 0xffffffffffffffc5;
    modulus: Mod,

    pub fn init() !dummyFf {
        const mod_ = try Mod.fromPrimitive(u64, PRIME);
        return .{ .modulus = mod_ };
    }
    pub fn importLittleEndian(self: dummyFf, bytes: []const u8) !Element {
        if (bytes.len != 8) {
            return error.InvalidLength;
        }
        const val_u64 = std.mem.readInt(u64,  @as(*const [8]u8, @ptrCast(bytes)), .little);
        return try self.modulus.Fe.fromPrimitive(u64, self.modulus, val_u64);
    }
};

test "PosiedonPRF is deterministic" {
    const field = try dummyFf.init();
    const PRF4 = PosiedonPRF(dummyFf, 4);
    var prf = PRF4.init(field);

    var key: PRF4.Key = undefined;
    for (0..@sizeOf(PRF4.Key)) |i| key[i] = @truncate(i);

    const epoch: u32 = 42;
    const index: u64 = 123456789;

    const out1 = prf.apply(&key, epoch, index);
    const out2 = prf.apply(&key, epoch, index);

    try std.testing.expectEqual(out1, out2);
}
test "PosiedonPRF changes when epoch changes" {
    const field = try dummyFf.init();
    const PRF4 = PosiedonPRF(dummyFf, 4);
    var prf = PRF4.init(field);

    var key: PRF4.Key = undefined;
    for (0..@sizeOf(PRF4.Key)) |i| key[i] = @truncate(i + 10);

    const index: u64 = 9999;
    const epoch1: u32 = 42;
    const epoch2: u32 = 43;

const out1 = try prf.apply(&key, epoch1, index);
const out2 = try prf.apply(&key, epoch2, index);


    try std.testing.expect(out1[0].v.limbs_buffer[0] != out2[0].v.limbs_buffer[0]);
}
