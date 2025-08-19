const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");

test "PASERK type identification" {
    // Test type constants
    try testing.expectEqualStrings("k4.local.", paserk.TYPE_LOCAL);
    try testing.expectEqualStrings("k4.public.", paserk.TYPE_PUBLIC);
    try testing.expectEqualStrings("k4.secret.", paserk.TYPE_SECRET);
    try testing.expectEqualStrings("k4.local-wrap.", paserk.TYPE_LOCAL_WRAP);
    try testing.expectEqualStrings("k4.secret-wrap.", paserk.TYPE_SECRET_WRAP);
    try testing.expectEqualStrings("k4.local-pw.", paserk.TYPE_LOCAL_PW);
    try testing.expectEqualStrings("k4.secret-pw.", paserk.TYPE_SECRET_PW);
    try testing.expectEqualStrings("k4.lid.", paserk.TYPE_LOCAL_ID);
    try testing.expectEqualStrings("k4.sid.", paserk.TYPE_SECRET_ID);
    try testing.expectEqualStrings("k4.pid.", paserk.TYPE_PUBLIC_ID);
}

test "PASERK type from string" {
    try testing.expectEqual(paserk.PaserkType.local, try paserk.typeFromString("k4.local."));
    try testing.expectEqual(paserk.PaserkType.public, try paserk.typeFromString("k4.public."));
    try testing.expectEqual(paserk.PaserkType.secret, try paserk.typeFromString("k4.secret."));
    try testing.expectEqual(paserk.PaserkType.local_wrap, try paserk.typeFromString("k4.local-wrap."));
    try testing.expectEqual(paserk.PaserkType.secret_wrap, try paserk.typeFromString("k4.secret-wrap."));
    try testing.expectEqual(paserk.PaserkType.local_pw, try paserk.typeFromString("k4.local-pw."));
    try testing.expectEqual(paserk.PaserkType.secret_pw, try paserk.typeFromString("k4.secret-pw."));
    try testing.expectEqual(paserk.PaserkType.local_id, try paserk.typeFromString("k4.lid."));
    try testing.expectEqual(paserk.PaserkType.secret_id, try paserk.typeFromString("k4.sid."));
    try testing.expectEqual(paserk.PaserkType.public_id, try paserk.typeFromString("k4.pid."));
    
    // Invalid types
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("k3.local."));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("k4.invalid."));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString("invalid"));
    try testing.expectError(errors.Error.InvalidPaserkType, paserk.typeFromString(""));
}

test "PASERK type to string" {
    try testing.expectEqualStrings("k4.local.", paserk.typeToString(.local));
    try testing.expectEqualStrings("k4.public.", paserk.typeToString(.public));
    try testing.expectEqualStrings("k4.secret.", paserk.typeToString(.secret));
    try testing.expectEqualStrings("k4.local-wrap.", paserk.typeToString(.local_wrap));
    try testing.expectEqualStrings("k4.secret-wrap.", paserk.typeToString(.secret_wrap));
    try testing.expectEqualStrings("k4.local-pw.", paserk.typeToString(.local_pw));
    try testing.expectEqualStrings("k4.secret-pw.", paserk.typeToString(.secret_pw));
    try testing.expectEqualStrings("k4.lid.", paserk.typeToString(.local_id));
    try testing.expectEqualStrings("k4.sid.", paserk.typeToString(.secret_id));
    try testing.expectEqualStrings("k4.pid.", paserk.typeToString(.public_id));
}

test "LocalKeyId generation from key" {
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const lid1 = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    const lid2 = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    
    // Should be deterministic
    try testing.expectEqualSlices(u8, lid1.bytes(), lid2.bytes());
    try testing.expectEqual(@as(usize, 33), lid1.bytes().len); // Version byte + 32 hash bytes
    try testing.expectEqual(@as(u8, 0x04), lid1.bytes()[0]); // Version 4
}

test "LocalKeyId different keys produce different IDs" {
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    const lid1 = paserk.LocalKeyId.fromLocalKey(key1.bytes());
    const lid2 = paserk.LocalKeyId.fromLocalKey(key2.bytes());
    
    try testing.expect(!mem.eql(u8, lid1.bytes(), lid2.bytes()));
}

test "LocalKeyId serialization" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const lid = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    const serialized = try lid.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.lid."));
    
    // Deserialize and verify
    const deserialized = try paserk.LocalKeyId.deserialize(serialized);
    try testing.expectEqualSlices(u8, lid.bytes(), deserialized.bytes());
}

test "SecretKeyId generation from secret key" {
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const sid1 = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    const sid2 = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    
    // Should be deterministic
    try testing.expectEqualSlices(u8, sid1.bytes(), sid2.bytes());
    try testing.expectEqual(@as(usize, 33), sid1.bytes().len);
    try testing.expectEqual(@as(u8, 0x04), sid1.bytes()[0]);
}

test "SecretKeyId from public key" {
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const sid_from_secret = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    const sid_from_public = paserk.SecretKeyId.fromPublicKey(keypair.public.bytes());
    
    // Should produce the same ID
    try testing.expectEqualSlices(u8, sid_from_secret.bytes(), sid_from_public.bytes());
}

test "SecretKeyId serialization" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const sid = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    const serialized = try sid.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.sid."));
    
    const deserialized = try paserk.SecretKeyId.deserialize(serialized);
    try testing.expectEqualSlices(u8, sid.bytes(), deserialized.bytes());
}

test "PublicKeyId generation from public key" {
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const pid1 = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    const pid2 = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    
    try testing.expectEqualSlices(u8, pid1.bytes(), pid2.bytes());
    try testing.expectEqual(@as(usize, 33), pid1.bytes().len);
    try testing.expectEqual(@as(u8, 0x04), pid1.bytes()[0]);
}

test "PublicKeyId from secret key" {
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const pid_from_public = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    const pid_from_secret = paserk.PublicKeyId.fromSecretKey(keypair.secret.bytes());
    
    // Should produce the same ID
    try testing.expectEqualSlices(u8, pid_from_public.bytes(), pid_from_secret.bytes());
}

test "PublicKeyId serialization" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const pid = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    const serialized = try pid.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(mem.startsWith(u8, serialized, "k4.pid."));
    
    const deserialized = try paserk.PublicKeyId.deserialize(serialized);
    try testing.expectEqualSlices(u8, pid.bytes(), deserialized.bytes());
}

test "key ID relationships" {
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const sid = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    const pid = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    const lid = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    
    // SecretKeyId and PublicKeyId from same keypair should be equal
    try testing.expectEqualSlices(u8, sid.bytes(), pid.bytes());
    
    // LocalKeyId should be different from asymmetric key IDs
    try testing.expect(!mem.eql(u8, lid.bytes(), sid.bytes()));
    try testing.expect(!mem.eql(u8, lid.bytes(), pid.bytes()));
}

test "key ID invalid serialization formats" {
    // Test invalid PASERK ID strings
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.LocalKeyId.deserialize("k3.lid.invalid"));
    
    try testing.expectError(errors.Error.InvalidPaserkType,
        paserk.LocalKeyId.deserialize("k4.invalid.data"));
    
    try testing.expectError(error.InvalidCharacter,
        paserk.LocalKeyId.deserialize("k4.lid."));
    
    try testing.expectError(error.InvalidCharacter,
        paserk.SecretKeyId.deserialize("k4.sid.invalid+base64"));
    
    try testing.expectError(errors.Error.InvalidKeyLength,
        paserk.PublicKeyId.deserialize("k4.pid.dGVzdA")); // Too short data
}

test "key ID deterministic generation" {
    const test_key_bytes = [_]u8{0x42} ** 32;
    
    const local_key = try v4.LocalKey.fromBytes(&test_key_bytes);
    
    const lid1 = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    const lid2 = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    
    // Multiple calls should produce identical results
    try testing.expectEqualSlices(u8, lid1.bytes(), lid2.bytes());
    
    // Different key should produce different ID
    const different_key_bytes = [_]u8{0x24} ** 32;
    const different_key = try v4.LocalKey.fromBytes(&different_key_bytes);
    const lid_different = paserk.LocalKeyId.fromLocalKey(different_key.bytes());
    
    try testing.expect(!mem.eql(u8, lid1.bytes(), lid_different.bytes()));
}

test "key ID edge cases" {
    // Test with all-zero keys
    const zero_key = [_]u8{0} ** 32;
    const zero_local = try v4.LocalKey.fromBytes(&zero_key);
    const zero_lid = paserk.LocalKeyId.fromLocalKey(zero_local.bytes());
    
    try testing.expectEqual(@as(usize, 33), zero_lid.bytes().len);
    try testing.expectEqual(@as(u8, 0x04), zero_lid.bytes()[0]);
    
    // Test with all-max keys
    const max_key = [_]u8{0xFF} ** 32;
    const max_local = try v4.LocalKey.fromBytes(&max_key);
    const max_lid = paserk.LocalKeyId.fromLocalKey(max_local.bytes());
    
    try testing.expectEqual(@as(usize, 33), max_lid.bytes().len);
    try testing.expectEqual(@as(u8, 0x04), max_lid.bytes()[0]);
    
    // Should be different
    try testing.expect(!mem.eql(u8, zero_lid.bytes(), max_lid.bytes()));
}

test "PASERK serialization round trip" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Test all ID types
    const lid = paserk.LocalKeyId.fromLocalKey(local_key.bytes());
    const sid = paserk.SecretKeyId.fromSecretKey(keypair.secret.bytes());
    const pid = paserk.PublicKeyId.fromPublicKey(keypair.public.bytes());
    
    // Serialize
    const lid_str = try lid.serialize(allocator);
    defer allocator.free(lid_str);
    const sid_str = try sid.serialize(allocator);
    defer allocator.free(sid_str);
    const pid_str = try pid.serialize(allocator);
    defer allocator.free(pid_str);
    
    // Deserialize
    const lid_back = try paserk.LocalKeyId.deserialize(lid_str);
    const sid_back = try paserk.SecretKeyId.deserialize(sid_str);
    const pid_back = try paserk.PublicKeyId.deserialize(pid_str);
    
    // Verify round trip
    try testing.expectEqualSlices(u8, lid.bytes(), lid_back.bytes());
    try testing.expectEqualSlices(u8, sid.bytes(), sid_back.bytes());
    try testing.expectEqualSlices(u8, pid.bytes(), pid_back.bytes());
}

test "PASERK header validation" {
    // Test header parsing
    try testing.expect(mem.startsWith(u8, "k4.local.abc", "k4.local."));
    try testing.expect(mem.startsWith(u8, "k4.public.xyz", "k4.public."));
    try testing.expect(!mem.startsWith(u8, "k3.local.abc", "k4.local."));
    try testing.expect(!mem.startsWith(u8, "v4.local.abc", "k4.local."));
    
    // Verify proper header lengths
    try testing.expectEqual(@as(usize, 9), "k4.local.".len);
    try testing.expectEqual(@as(usize, 10), "k4.public.".len);
    try testing.expectEqual(@as(usize, 10), "k4.secret.".len);
    try testing.expectEqual(@as(usize, 14), "k4.local-wrap.".len);
    try testing.expectEqual(@as(usize, 15), "k4.secret-wrap.".len);
    try testing.expectEqual(@as(usize, 11), "k4.local-pw.".len);
    try testing.expectEqual(@as(usize, 12), "k4.secret-pw.".len);
    try testing.expectEqual(@as(usize, 7), "k4.lid.".len);
    try testing.expectEqual(@as(usize, 7), "k4.sid.".len);
    try testing.expectEqual(@as(usize, 7), "k4.pid.".len);
}