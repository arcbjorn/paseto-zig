const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const crypto = std.crypto;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");
const utils = @import("../src/utils.zig");

test "constant time comparison security" {
    // Test that constant time comparison doesn't leak timing information
    // This is a basic functional test - timing analysis would require specialized tools
    
    const secret1 = "super-secret-value-123";
    const secret2 = "super-secret-value-456";
    const secret3 = "completely-different";
    const secret4 = "super-secret-value-123"; // Same as secret1
    
    // Different values should return false
    try testing.expect(!utils.constantTimeEqual(secret1, secret2));
    try testing.expect(!utils.constantTimeEqual(secret1, secret3));
    try testing.expect(!utils.constantTimeEqual(secret2, secret3));
    
    // Same values should return true
    try testing.expect(utils.constantTimeEqual(secret1, secret4));
    
    // Different lengths should return false quickly but securely
    try testing.expect(!utils.constantTimeEqual("short", "much-longer-string"));
    try testing.expect(!utils.constantTimeEqual("", "non-empty"));
}

test "memory zeroing security" {
    var sensitive_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    
    // Verify data is not zero initially
    var all_zero = true;
    for (sensitive_data) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
    
    // Zero the data
    utils.secureZero(&sensitive_data);
    
    // Verify all bytes are now zero
    for (sensitive_data) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "key generation randomness" {
    // Test that key generation produces different keys
    var keys: [10]v4.LocalKey = undefined;
    for (keys, 0..) |*key, i| {
        key.* = v4.LocalKey.generate();
        
        // Compare with all previous keys
        for (keys[0..i]) |prev_key| {
            try testing.expect(!mem.eql(u8, key.bytes(), prev_key.bytes()));
        }
    }
    
    // Cleanup
    for (keys) |*key| {
        key.deinit();
    }
}

test "nonce uniqueness in encryption" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "repeated encryption test";
    var tokens: [50][]u8 = undefined;
    
    // Generate many tokens with same key and payload
    for (tokens, 0..) |*token, i| {
        _ = i;
        token.* = try v4.encryptLocal(allocator, payload, &key, null, null);
    }
    defer {
        for (tokens) |token| {
            allocator.free(token);
        }
    }
    
    // All tokens should be different (due to random nonces)
    for (tokens, 0..) |token1, i| {
        for (tokens[i + 1..]) |token2| {
            try testing.expect(!mem.eql(u8, token1, token2));
        }
    }
    
    // But all should decrypt to same payload
    for (tokens) |token| {
        const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(payload, decrypted);
    }
}

test "signature determinism security" {
    const allocator = testing.allocator;
    
    const seed = [_]u8{0x42} ** 32;
    var keypair1 = try v4.KeyPair.fromSeed(&seed);
    defer keypair1.deinit();
    
    var keypair2 = try v4.KeyPair.fromSeed(&seed);
    defer keypair2.deinit();
    
    const payload = "deterministic signature test";
    
    const sig1 = try v4.signPublic(allocator, payload, &keypair1.secret, null, null);
    defer allocator.free(sig1);
    
    const sig2 = try v4.signPublic(allocator, payload, &keypair2.secret, null, null);
    defer allocator.free(sig2);
    
    // Ed25519 signatures should be deterministic with same key and message
    try testing.expectEqualStrings(sig1, sig2);
    
    // Both should verify
    const verified1 = try v4.verifyPublic(allocator, sig1, &keypair1.public, null, null);
    defer allocator.free(verified1);
    const verified2 = try v4.verifyPublic(allocator, sig2, &keypair2.public, null, null);
    defer allocator.free(verified2);
    
    try testing.expectEqualStrings(payload, verified1);
    try testing.expectEqualStrings(payload, verified2);
}

test "token tampering detection" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const original_payload = "important data";
    var token = try v4.encryptLocal(allocator, original_payload, &key, null, null);
    defer allocator.free(token);
    
    // Make a copy to tamper with
    var tampered_token = try allocator.dupe(u8, token);
    defer allocator.free(tampered_token);
    
    // Tamper with different parts of the token
    const positions_to_tamper = [_]usize{ 15, 25, 35, tampered_token.len - 10 };
    
    for (positions_to_tamper) |pos| {
        if (pos < tampered_token.len) {
            // Restore original
            @memcpy(tampered_token, token);
            
            // Tamper with one byte
            tampered_token[pos] = if (tampered_token[pos] == 'A') 'B' else 'A';
            
            // Should fail to decrypt
            try testing.expectError(errors.Error.InvalidSignature,
                v4.decryptLocal(allocator, tampered_token, &key, null, null));
        }
    }
}

test "public key signature tampering" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const original_payload = "signed message";
    var token = try v4.signPublic(allocator, original_payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    // Make copy to tamper with
    var tampered = try allocator.dupe(u8, token);
    defer allocator.free(tampered);
    
    // Tamper with signature portion (end of token)
    if (tampered.len > 10) {
        tampered[tampered.len - 5] = if (tampered[tampered.len - 5] == 'A') 'B' else 'A';
        
        try testing.expectError(errors.Error.InvalidSignature,
            v4.verifyPublic(allocator, tampered, &keypair.public, null, null));
    }
}

test "cross-key contamination prevention" {
    const allocator = testing.allocator;
    
    // Generate multiple keys
    var local_key1 = v4.LocalKey.generate();
    defer local_key1.deinit();
    var local_key2 = v4.LocalKey.generate();
    defer local_key2.deinit();
    
    var keypair1 = v4.KeyPair.generate();
    defer keypair1.deinit();
    var keypair2 = v4.KeyPair.generate();
    defer keypair2.deinit();
    
    const payload = "cross-key test";
    
    // Create tokens with different keys
    const local_token1 = try v4.encryptLocal(allocator, payload, &local_key1, null, null);
    defer allocator.free(local_token1);
    
    const public_token1 = try v4.signPublic(allocator, payload, &keypair1.secret, null, null);
    defer allocator.free(public_token1);
    
    // Verify tokens cannot be used with wrong keys
    try testing.expectError(errors.Error.InvalidSignature,
        v4.decryptLocal(allocator, local_token1, &local_key2, null, null));
    
    try testing.expectError(errors.Error.InvalidSignature,
        v4.verifyPublic(allocator, public_token1, &keypair2.public, null, null));
    
    // Verify tokens cannot be used with wrong token types
    var parser = v4.Parser.init(allocator);
    parser.setValidateTime(false);
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parsePublic(local_token1, &keypair1.public, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        parser.parseLocal(public_token1, &local_key1, null, null));
}

test "timing attack resistance in comparisons" {
    // Test that string comparisons don't leak length information
    const short_str = "abc";
    const long_str = "a very long string that is much longer than the short one";
    const same_length_different = "xyz";
    const same_as_short = "abc";
    
    // All false comparisons should take similar time regardless of where difference occurs
    try testing.expect(!utils.constantTimeEqual(short_str, long_str));
    try testing.expect(!utils.constantTimeEqual(short_str, same_length_different));
    try testing.expect(!utils.constantTimeEqual(long_str, same_length_different));
    
    // True comparison should work
    try testing.expect(utils.constantTimeEqual(short_str, same_as_short));
}

test "key derivation consistency" {
    // Test that same seeds always produce same keys
    const test_seeds = [_][32]u8{
        [_]u8{0x01} ** 32,
        [_]u8{0xFF} ** 32,
        [_]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    };
    
    for (test_seeds) |seed| {
        const key1 = try v4.SecretKey.fromSeed(&seed);
        const key2 = try v4.SecretKey.fromSeed(&seed);
        
        // Should be identical
        try testing.expectEqualSlices(u8, key1.bytes(), key2.bytes());
        try testing.expectEqualSlices(u8, key1.seed(), key2.seed());
        
        // Public keys should also be identical
        const pub1 = key1.publicKey();
        const pub2 = key2.publicKey();
        try testing.expectEqualSlices(u8, pub1.bytes(), pub2.bytes());
    }
}

test "PASERK key ID collision resistance" {
    // Test that different keys produce different IDs
    var keys: [20]v4.LocalKey = undefined;
    var ids: [20]paserk.LocalKeyId = undefined;
    
    for (keys, 0..) |*key, i| {
        var seed: [32]u8 = undefined;
        std.mem.writeInt(u64, seed[0..8], @as(u64, @intCast(i)), .little);
        std.mem.writeInt(u64, seed[8..16], @as(u64, @intCast(i * 2)), .little);
        std.mem.writeInt(u64, seed[16..24], @as(u64, @intCast(i * 3)), .little);
        std.mem.writeInt(u64, seed[24..32], @as(u64, @intCast(i * 5)), .little);
        
        key.* = try v4.LocalKey.fromBytes(&seed);
        ids[i] = paserk.LocalKeyId.fromLocalKey(key.bytes());
        
        // Check against all previous IDs
        for (ids[0..i]) |prev_id| {
            try testing.expect(!mem.eql(u8, ids[i].bytes(), prev_id.bytes()));
        }
    }
}

test "password-based key derivation consistency" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "test-password-123";
    const salt = [_]u8{0x12, 0x34, 0x56, 0x78} ** 4; // 16 bytes
    const options = paserk.PasswordOptions{ 
        .iterations = 1000,
        .salt = &salt
    };
    
    // Wrap multiple times with same parameters
    const wrapped1 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, &local_key, password, options);
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, &local_key, password, options);
    defer allocator.free(wrapped2);
    
    // Should be identical with same salt
    try testing.expectEqualStrings(wrapped1, wrapped2);
    
    // Should unwrap to same key
    const unwrapped1 = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, wrapped1, password);
    const unwrapped2 = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, wrapped2, password);
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped1.bytes());
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped2.bytes());
}

test "large payload handling security" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Test with very large payload
    const large_payload = try allocator.alloc(u8, 1024 * 1024); // 1MB
    defer allocator.free(large_payload);
    
    // Fill with pattern to detect corruption
    for (large_payload, 0..) |*byte, i| {
        byte.* = @intCast((i * 7 + 13) % 256);
    }
    
    const token = try v4.encryptLocal(allocator, large_payload, &key, null, null);
    defer allocator.free(token);
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    // Verify complete payload integrity
    try testing.expectEqualSlices(u8, large_payload, decrypted);
}

test "footer injection prevention" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "test payload";
    const malicious_footer = "malicious.v4.local.fake_token_data";
    
    const token = try v4.encryptLocal(allocator, payload, &key, malicious_footer, null);
    defer allocator.free(token);
    
    // Token should be properly structured despite malicious footer
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
    try testing.expect(mem.endsWith(u8, token, malicious_footer));
    
    // Should only decrypt with correct footer
    const decrypted = try v4.decryptLocal(allocator, token, &key, malicious_footer, null);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(payload, decrypted);
    
    // Should fail with different footer
    try testing.expectError(errors.Error.InvalidFooter,
        v4.decryptLocal(allocator, token, &key, "different-footer", null));
}

test "base64url encoding security properties" {
    const allocator = testing.allocator;
    
    // Test that base64url encoding is URL-safe and has no padding
    const test_data = [_]u8{ 0xFF, 0xFE, 0xFD, 0x3E, 0x3F, 0x00, 0x01 };
    
    const encoded = try utils.base64urlEncode(allocator, &test_data);
    defer allocator.free(encoded);
    
    // Should not contain URL-unsafe characters
    try testing.expect(mem.indexOf(u8, encoded, "+") == null);
    try testing.expect(mem.indexOf(u8, encoded, "/") == null);
    try testing.expect(mem.indexOf(u8, encoded, "=") == null);
    
    // Should decode back correctly
    const decoded = try utils.base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &test_data, decoded);
}

test "implicit assertion binding security" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "sensitive data";
    const context1 = "user-session-123";
    const context2 = "user-session-456";
    
    // Create tokens with different implicit assertions
    const token1 = try v4.encryptLocal(allocator, payload, &key, null, context1);
    defer allocator.free(token1);
    
    const token2 = try v4.encryptLocal(allocator, payload, &key, null, context2);
    defer allocator.free(token2);
    
    // Tokens should be different despite same key and payload
    try testing.expect(!mem.eql(u8, token1, token2));
    
    // Each should only decrypt with its own context
    const decrypted1 = try v4.decryptLocal(allocator, token1, &key, null, context1);
    defer allocator.free(decrypted1);
    try testing.expectEqualStrings(payload, decrypted1);
    
    const decrypted2 = try v4.decryptLocal(allocator, token2, &key, null, context2);
    defer allocator.free(decrypted2);
    try testing.expectEqualStrings(payload, decrypted2);
    
    // Cross-context decryption should fail
    try testing.expectError(errors.Error.InvalidSignature,
        v4.decryptLocal(allocator, token1, &key, null, context2));
    
    try testing.expectError(errors.Error.InvalidSignature,
        v4.decryptLocal(allocator, token2, &key, null, context1));
}

test "key wrapping security properties" {
    const allocator = testing.allocator;
    
    var target_key = v4.LocalKey.generate();
    defer target_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap the same key multiple times
    var wrapped_keys: [5][]u8 = undefined;
    for (wrapped_keys, 0..) |*wrapped, i| {
        _ = i;
        wrapped.* = try paserk.wrapLocalKeyWithLocalKey(allocator, &target_key, &wrapping_key);
    }
    defer {
        for (wrapped_keys) |wrapped| {
            allocator.free(wrapped);
        }
    }
    
    // All wrapped versions should be different (different nonces)
    for (wrapped_keys, 0..) |wrapped1, i| {
        for (wrapped_keys[i + 1..]) |wrapped2| {
            try testing.expect(!mem.eql(u8, wrapped1, wrapped2));
        }
    }
    
    // But all should unwrap to the same key
    for (wrapped_keys) |wrapped| {
        const unwrapped = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped, &wrapping_key);
        try testing.expectEqualSlices(u8, target_key.bytes(), unwrapped.bytes());
    }
}

test "side channel resistance in key operations" {
    // Test that key operations don't leak information through exceptions
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    // Operations with wrong keys should fail consistently
    var successes: u32 = 0;
    var failures: u32 = 0;
    
    for (0..100) |_| {
        const allocator = testing.allocator;
        
        const token = try v4.encryptLocal(allocator, "test", &key1, null, null);
        defer allocator.free(token);
        
        const result = v4.decryptLocal(allocator, token, &key2, null, null);
        if (result) |decrypted| {
            allocator.free(decrypted);
            successes += 1;
        } else |_| {
            failures += 1;
        }
    }
    
    // All operations should fail with wrong key
    try testing.expectEqual(@as(u32, 0), successes);
    try testing.expectEqual(@as(u32, 100), failures);
}