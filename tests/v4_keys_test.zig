const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const crypto = std.crypto;

const v4 = @import("../src/v4/mod.zig");
const errors = @import("../src/errors.zig");

test "LocalKey generation" {
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    // Keys should be different
    try testing.expect(!mem.eql(u8, key1.bytes(), key2.bytes()));
    
    // Keys should be 32 bytes
    try testing.expectEqual(@as(usize, 32), key1.bytes().len);
    try testing.expectEqual(@as(usize, 32), key2.bytes().len);
}

test "LocalKey from bytes valid" {
    const key_bytes = [_]u8{0xAA} ** 32;
    const key = try v4.LocalKey.fromBytes(&key_bytes);
    
    try testing.expectEqualSlices(u8, &key_bytes, key.bytes());
}

test "LocalKey from bytes invalid length" {
    // Too short
    const short_bytes = [_]u8{0xAA} ** 16;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&short_bytes));
    
    // Too long
    const long_bytes = [_]u8{0xAA} ** 64;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&long_bytes));
    
    // Empty
    try testing.expectError(errors.Error.InvalidKeyLength, v4.LocalKey.fromBytes(&[_]u8{}));
}

test "LocalKey secure cleanup" {
    var key = v4.LocalKey.generate();
    const original_bytes = key.bytes().*;
    
    // Verify key is not all zeros initially
    var all_zeros = true;
    for (original_bytes) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
    
    key.deinit();
    
    // After deinit, key material should be zeroed
    for (key.bytes()) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "SecretKey generation" {
    var key1 = v4.SecretKey.generate();
    defer key1.deinit();
    
    var key2 = v4.SecretKey.generate();
    defer key2.deinit();
    
    // Keys should be different
    try testing.expect(!mem.eql(u8, key1.bytes(), key2.bytes()));
    try testing.expect(!mem.eql(u8, key1.seed(), key2.seed()));
    
    // Keys should be 64 bytes total (32 seed + 32 public)
    try testing.expectEqual(@as(usize, 64), key1.bytes().len);
    try testing.expectEqual(@as(usize, 32), key1.seed().len);
}

test "SecretKey from seed" {
    const seed = [_]u8{0x42} ** 32;
    const key = try v4.SecretKey.fromSeed(&seed);
    
    // Seed should match
    try testing.expectEqualSlices(u8, &seed, key.seed());
    
    // Key should be deterministic from seed
    const key2 = try v4.SecretKey.fromSeed(&seed);
    try testing.expectEqualSlices(u8, key.bytes(), key2.bytes());
}

test "SecretKey from seed invalid length" {
    // Too short
    const short_seed = [_]u8{0x42} ** 16;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&short_seed));
    
    // Too long
    const long_seed = [_]u8{0x42} ** 64;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&long_seed));
    
    // Empty
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromSeed(&[_]u8{}));
}

test "SecretKey from bytes" {
    const key_bytes = [_]u8{0x33} ** 64;
    const key = try v4.SecretKey.fromBytes(&key_bytes);
    
    try testing.expectEqualSlices(u8, &key_bytes, key.bytes());
    try testing.expectEqualSlices(u8, key_bytes[0..32], key.seed());
}

test "SecretKey from bytes invalid length" {
    // Wrong length
    const wrong_bytes = [_]u8{0x33} ** 32;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.SecretKey.fromBytes(&wrong_bytes));
}

test "SecretKey public key extraction" {
    var secret = v4.SecretKey.generate();
    defer secret.deinit();
    
    const public_key = secret.publicKey();
    
    // Public key should be 32 bytes
    try testing.expectEqual(@as(usize, 32), public_key.bytes().len);
    
    // Public key should match the second half of secret key
    try testing.expectEqualSlices(u8, public_key.bytes(), secret.bytes()[32..64]);
}

test "PublicKey from bytes" {
    const key_bytes = [_]u8{0x55} ** 32;
    const key = try v4.PublicKey.fromBytes(&key_bytes);
    
    try testing.expectEqualSlices(u8, &key_bytes, key.bytes());
}

test "PublicKey from bytes invalid length" {
    // Too short
    const short_bytes = [_]u8{0x55} ** 16;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.PublicKey.fromBytes(&short_bytes));
    
    // Too long
    const long_bytes = [_]u8{0x55} ** 64;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.PublicKey.fromBytes(&long_bytes));
}

test "KeyPair generation" {
    var keypair1 = v4.KeyPair.generate();
    defer keypair1.deinit();
    
    var keypair2 = v4.KeyPair.generate();
    defer keypair2.deinit();
    
    // Keypairs should be different
    try testing.expect(!mem.eql(u8, keypair1.secret.bytes(), keypair2.secret.bytes()));
    try testing.expect(!mem.eql(u8, keypair1.public.bytes(), keypair2.public.bytes()));
    
    // Public key should match extracted public key from secret
    const extracted_public = keypair1.secret.publicKey();
    try testing.expectEqualSlices(u8, keypair1.public.bytes(), extracted_public.bytes());
}

test "KeyPair from secret key" {
    var secret = v4.SecretKey.generate();
    defer secret.deinit();
    
    var keypair = v4.KeyPair.fromSecretKey(secret);
    defer keypair.deinit();
    
    // Secret keys should match
    try testing.expectEqualSlices(u8, secret.bytes(), keypair.secret.bytes());
    
    // Public key should be correctly derived
    const expected_public = secret.publicKey();
    try testing.expectEqualSlices(u8, expected_public.bytes(), keypair.public.bytes());
}

test "KeyPair from seed" {
    const seed = [_]u8{0x77} ** 32;
    
    var keypair1 = try v4.KeyPair.fromSeed(&seed);
    defer keypair1.deinit();
    
    var keypair2 = try v4.KeyPair.fromSeed(&seed);
    defer keypair2.deinit();
    
    // Keypairs from same seed should be identical
    try testing.expectEqualSlices(u8, keypair1.secret.bytes(), keypair2.secret.bytes());
    try testing.expectEqualSlices(u8, keypair1.public.bytes(), keypair2.public.bytes());
    
    // Seed should match
    try testing.expectEqualSlices(u8, &seed, keypair1.secret.seed());
}

test "KeyPair from seed invalid length" {
    const invalid_seed = [_]u8{0x77} ** 16;
    try testing.expectError(errors.Error.InvalidKeyLength, v4.KeyPair.fromSeed(&invalid_seed));
}

test "key type separation" {
    // Verify that different key types can't be confused
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // LocalKey is 32 bytes, SecretKey/PublicKey are different sizes
    try testing.expectEqual(@as(usize, 32), local_key.bytes().len);
    try testing.expectEqual(@as(usize, 64), keypair.secret.bytes().len);
    try testing.expectEqual(@as(usize, 32), keypair.public.bytes().len);
    
    // Verify they're truly different types (compile-time check)
    // These would cause compile errors if types were confused:
    // const wrong1: v4.LocalKey = keypair.secret; // Error
    // const wrong2: v4.SecretKey = local_key; // Error
}

test "deterministic key generation from same seed" {
    const seed = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    
    const key1 = try v4.SecretKey.fromSeed(&seed);
    const key2 = try v4.SecretKey.fromSeed(&seed);
    
    try testing.expectEqualSlices(u8, key1.bytes(), key2.bytes());
    try testing.expectEqualSlices(u8, key1.seed(), key2.seed());
    
    const pub1 = key1.publicKey();
    const pub2 = key2.publicKey();
    try testing.expectEqualSlices(u8, pub1.bytes(), pub2.bytes());
}

test "key material independence" {
    // Verify that different keys don't share memory
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    // Modifying one shouldn't affect the other
    const ptr1 = @intFromPtr(key1.bytes());
    const ptr2 = @intFromPtr(key2.bytes());
    
    try testing.expect(ptr1 != ptr2);
}

test "secret key secure cleanup" {
    var secret = v4.SecretKey.generate();
    const original_bytes = secret.bytes().*;
    
    // Verify key is not all zeros initially
    var all_zeros = true;
    for (original_bytes) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);
    
    secret.deinit();
    
    // After deinit, key material should be zeroed
    for (secret.bytes()) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "keypair secure cleanup" {
    var keypair = v4.KeyPair.generate();
    const original_secret = keypair.secret.bytes().*;
    
    keypair.deinit();
    
    // Secret key should be zeroed
    for (keypair.secret.bytes()) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
    
    // Note: PublicKey doesn't need secure cleanup as it's not sensitive
}

test "Token struct basic operations" {
    const allocator = testing.allocator;
    
    const header = try allocator.dupe(u8, "v4.local.");
    const payload = try allocator.dupe(u8, "test payload");
    const footer = try allocator.dupe(u8, "test footer");
    
    const token = v4.Token{
        .header = header,
        .payload = payload,
        .footer = footer,
    };
    
    // Verify fields
    try testing.expectEqualStrings("v4.local.", token.header);
    try testing.expectEqualStrings("test payload", token.payload);
    try testing.expectEqualStrings("test footer", token.footer);
    
    // Cleanup
    token.deinit(allocator);
}

test "key validation edge cases" {
    // Test with all zeros
    const zero_key = [_]u8{0} ** 32;
    const local_key = try v4.LocalKey.fromBytes(&zero_key);
    try testing.expectEqualSlices(u8, &zero_key, local_key.bytes());
    
    // Test with all 0xFF
    const max_key = [_]u8{0xFF} ** 32;
    const local_key2 = try v4.LocalKey.fromBytes(&max_key);
    try testing.expectEqualSlices(u8, &max_key, local_key2.bytes());
    
    // Test with pattern
    var pattern_key: [32]u8 = undefined;
    for (pattern_key, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    const local_key3 = try v4.LocalKey.fromBytes(&pattern_key);
    try testing.expectEqualSlices(u8, &pattern_key, local_key3.bytes());
}

test "Algorithm Lucidity - Key type identification" {
    // Test that keys correctly identify their version and purpose
    
    // Local key should identify as v4.local
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    try testing.expect(local_key.isKeyValidFor(.v4, .local));
    try testing.expect(!local_key.isKeyValidFor(.v4, .public));
    
    // Secret key should identify as v4.public
    var secret_key = v4.SecretKey.generate();
    defer secret_key.deinit();
    
    try testing.expect(secret_key.isKeyValidFor(.v4, .public));
    try testing.expect(!secret_key.isKeyValidFor(.v4, .local));
    
    // Public key should identify as v4.public
    const public_key = secret_key.publicKey();
    try testing.expect(public_key.isKeyValidFor(.v4, .public));
    try testing.expect(!public_key.isKeyValidFor(.v4, .local));
}

test "Algorithm Lucidity - Prevents key confusion attacks" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    // Manually corrupt the purpose to simulate an attack
    local_key.purpose = .public; // Wrong purpose for local key
    
    const payload = "test payload";
    
    // Should fail during encryption due to algorithm lucidity
    try testing.expectError(errors.Error.KeyTypeMismatch,
        v4.encryptLocal(allocator, payload, &local_key, null, null));
}

test "Algorithm Lucidity - Public key confusion prevention" {
    const allocator = testing.allocator;
    
    var key_pair = v4.KeyPair.generate();
    defer key_pair.deinit();
    
    // Create a valid token first
    const payload = "test payload";
    const token = try v4.signPublic(allocator, payload, &key_pair.secret, null, null);
    defer allocator.free(token);
    
    // Corrupt the public key's purpose
    var public_key = key_pair.public;
    public_key.purpose = .local; // Wrong purpose
    
    // Should fail during verification
    try testing.expectError(errors.Error.KeyTypeMismatch,
        v4.verifyPublic(allocator, token, &public_key, null, null));
}

test "Algorithm Lucidity - Version and Purpose enums" {
    try testing.expectEqualStrings("v4", v4.Version.v4.toString());
    try testing.expectEqualStrings("local", v4.Purpose.local.toString());
    try testing.expectEqualStrings("public", v4.Purpose.public.toString());
}

test "Algorithm Lucidity - Key derivation preserves type" {
    var secret_key = v4.SecretKey.generate();
    defer secret_key.deinit();
    
    const public_key = secret_key.publicKey();
    
    // Both should be v4.public
    try testing.expect(secret_key.isKeyValidFor(.v4, .public));
    try testing.expect(public_key.isKeyValidFor(.v4, .public));
    
    // Neither should be local
    try testing.expect(!secret_key.isKeyValidFor(.v4, .local));
    try testing.expect(!public_key.isKeyValidFor(.v4, .local));
}