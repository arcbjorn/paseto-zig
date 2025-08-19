const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");

test "local key wrapping basic" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap the key
    const wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.local-wrap."));
    
    // Unwrap and verify
    const unwrapped = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped, &wrapping_key);
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "local key wrapping deterministic with nonce" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    const nonce = [_]u8{0x42} ** 32;
    
    // Wrap with same nonce twice
    const wrapped1 = try paserk.wrapLocalKeyWithLocalKeyAndNonce(
        allocator, 
        &local_key, 
        &wrapping_key, 
        &nonce
    );
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.wrapLocalKeyWithLocalKeyAndNonce(
        allocator, 
        &local_key, 
        &wrapping_key, 
        &nonce
    );
    defer allocator.free(wrapped2);
    
    // Should be identical with same nonce
    try testing.expectEqualStrings(wrapped1, wrapped2);
}

test "local key wrapping random nonce" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap without specifying nonce (should use random)
    const wrapped1 = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(wrapped2);
    
    // Should be different with random nonces
    try testing.expect(!mem.eql(u8, wrapped1, wrapped2));
    
    // But both should unwrap to same key
    const unwrapped1 = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped1, &wrapping_key);
    const unwrapped2 = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped2, &wrapping_key);
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped1.bytes());
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped2.bytes());
    try testing.expectEqualSlices(u8, unwrapped1.bytes(), unwrapped2.bytes());
}

test "local key wrapping wrong key fails" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key1 = v4.LocalKey.generate();
    defer wrapping_key1.deinit();
    
    var wrapping_key2 = v4.LocalKey.generate();
    defer wrapping_key2.deinit();
    
    // Wrap with key1
    const wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key1);
    defer allocator.free(wrapped);
    
    // Try to unwrap with key2 - should fail
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped, &wrapping_key2));
}

test "secret key wrapping basic" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap the secret key
    const wrapped = try paserk.wrapSecretKeyWithLocalKey(allocator, &keypair.secret, &wrapping_key);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.secret-wrap."));
    
    // Unwrap and verify
    const unwrapped = try paserk.unwrapSecretKeyWithLocalKey(allocator, wrapped, &wrapping_key);
    
    try testing.expectEqualSlices(u8, keypair.secret.bytes(), unwrapped.bytes());
}

test "secret key wrapping with asymmetric key" {
    const allocator = testing.allocator;
    
    var keypair_to_wrap = v4.KeyPair.generate();
    defer keypair_to_wrap.deinit();
    
    var wrapping_keypair = v4.KeyPair.generate();
    defer wrapping_keypair.deinit();
    
    // Wrap secret key with public key
    const wrapped = try paserk.wrapSecretKeyWithPublicKey(
        allocator, 
        &keypair_to_wrap.secret, 
        &wrapping_keypair.public
    );
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.secret-wrap."));
    
    // Unwrap with corresponding secret key
    const unwrapped = try paserk.unwrapSecretKeyWithSecretKey(
        allocator, 
        wrapped, 
        &wrapping_keypair.secret
    );
    
    try testing.expectEqualSlices(u8, keypair_to_wrap.secret.bytes(), unwrapped.bytes());
}

test "asymmetric wrapping wrong key fails" {
    const allocator = testing.allocator;
    
    var keypair_to_wrap = v4.KeyPair.generate();
    defer keypair_to_wrap.deinit();
    
    var wrapping_keypair1 = v4.KeyPair.generate();
    defer wrapping_keypair1.deinit();
    
    var wrapping_keypair2 = v4.KeyPair.generate();
    defer wrapping_keypair2.deinit();
    
    // Wrap with keypair1's public key
    const wrapped = try paserk.wrapSecretKeyWithPublicKey(
        allocator, 
        &keypair_to_wrap.secret, 
        &wrapping_keypair1.public
    );
    defer allocator.free(wrapped);
    
    // Try to unwrap with keypair2's secret key - should fail
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.unwrapSecretKeyWithSecretKey(allocator, wrapped, &wrapping_keypair2.secret));
}

test "wrapping format validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    const wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(wrapped);
    
    // Verify format
    try testing.expect(mem.startsWith(u8, wrapped, "k4.local-wrap."));
    
    // Should be base64url (no padding, no + or /)
    const data_part = wrapped["k4.local-wrap.".len..];
    try testing.expect(mem.indexOf(u8, data_part, "=") == null);
    try testing.expect(mem.indexOf(u8, data_part, "+") == null);
    try testing.expect(mem.indexOf(u8, data_part, "/") == null);
}

test "wrapping invalid input format" {
    const allocator = testing.allocator;
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Test various invalid formats
    const invalid_inputs = [_][]const u8{
        "k3.local-wrap.dGVzdA", // Wrong version
        "k4.secret-wrap.dGVzdA", // Wrong type for local unwrap
        "k4.local-wrap.", // Empty data
        "k4.local-wrap.invalid+base64", // Invalid base64url
        "k4.local-wrap.dGVzdA", // Too short data
    };
    
    for (invalid_inputs) |input| {
        const result = paserk.unwrapLocalKeyWithLocalKey(allocator, input, &wrapping_key);
        try testing.expect(std.meta.isError(result));
    }
}

test "wrapping with different nonces" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Test with different nonces
    const nonce1 = [_]u8{0x01} ** 32;
    const nonce2 = [_]u8{0x02} ** 32;
    
    const wrapped1 = try paserk.wrapLocalKeyWithLocalKeyAndNonce(
        allocator, 
        &local_key, 
        &wrapping_key, 
        &nonce1
    );
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.wrapLocalKeyWithLocalKeyAndNonce(
        allocator, 
        &local_key, 
        &wrapping_key, 
        &nonce2
    );
    defer allocator.free(wrapped2);
    
    // Should be different
    try testing.expect(!mem.eql(u8, wrapped1, wrapped2));
    
    // But both should unwrap correctly
    const unwrapped1 = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped1, &wrapping_key);
    const unwrapped2 = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped2, &wrapping_key);
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped1.bytes());
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped2.bytes());
}

test "wrapping corrupted data fails" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    var wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(wrapped);
    
    // Make a copy to corrupt
    var corrupted = try allocator.dupe(u8, wrapped);
    defer allocator.free(corrupted);
    
    // Corrupt different parts
    if (corrupted.len > 20) {
        // Corrupt in the middle
        corrupted[15] = if (corrupted[15] == 'A') 'B' else 'A';
        
        try testing.expectError(errors.Error.InvalidSignature,
            paserk.unwrapLocalKeyWithLocalKey(allocator, corrupted, &wrapping_key));
    }
}

test "wrapping edge case keys" {
    const allocator = testing.allocator;
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Test with edge case keys
    const zero_key = try v4.LocalKey.fromBytes(&([_]u8{0} ** 32));
    const max_key = try v4.LocalKey.fromBytes(&([_]u8{0xFF} ** 32));
    
    var pattern_bytes: [32]u8 = undefined;
    for (pattern_bytes, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    const pattern_key = try v4.LocalKey.fromBytes(&pattern_bytes);
    
    const test_keys = [_]v4.LocalKey{ zero_key, max_key, pattern_key };
    
    for (test_keys) |key| {
        const wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &key, &wrapping_key);
        defer allocator.free(wrapped);
        
        const unwrapped = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped, &wrapping_key);
        try testing.expectEqualSlices(u8, key.bytes(), unwrapped.bytes());
    }
}

test "wrapping multiple rounds" {
    const allocator = testing.allocator;
    
    var original_key = v4.LocalKey.generate();
    defer original_key.deinit();
    
    var wrapping_key1 = v4.LocalKey.generate();
    defer wrapping_key1.deinit();
    
    var wrapping_key2 = v4.LocalKey.generate();
    defer wrapping_key2.deinit();
    
    // Wrap with first key
    const wrapped1 = try paserk.wrapLocalKeyWithLocalKey(allocator, &original_key, &wrapping_key1);
    defer allocator.free(wrapped1);
    
    // Unwrap to get intermediate key
    const intermediate = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped1, &wrapping_key1);
    
    // Wrap again with second key
    const wrapped2 = try paserk.wrapLocalKeyWithLocalKey(allocator, &intermediate, &wrapping_key2);
    defer allocator.free(wrapped2);
    
    // Unwrap both layers
    const unwrapped1 = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped2, &wrapping_key2);
    const final_key = try paserk.unwrapLocalKeyWithLocalKey(allocator, wrapped1, &wrapping_key1);
    
    // Should match original
    try testing.expectEqualSlices(u8, original_key.bytes(), unwrapped1.bytes());
    try testing.expectEqualSlices(u8, original_key.bytes(), final_key.bytes());
}

test "wrapping length validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    const local_wrapped = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    defer allocator.free(local_wrapped);
    
    const secret_wrapped = try paserk.wrapSecretKeyWithLocalKey(allocator, &keypair.secret, &wrapping_key);
    defer allocator.free(secret_wrapped);
    
    // Local wrapped: header + base64url(nonce + encrypted_key + tag)
    //               = k4.local-wrap. + base64url(32 + 32 + 16) = 14 + 107 = 121
    try testing.expectEqual(@as(usize, 121), local_wrapped.len);
    
    // Secret wrapped: header + base64url(nonce + encrypted_key + tag)
    //                = k4.secret-wrap. + base64url(32 + 64 + 16) = 15 + 150 = 165
    try testing.expectEqual(@as(usize, 165), secret_wrapped.len);
}

test "wrapping concurrent operations" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Perform multiple wrap/unwrap operations "concurrently"
    var wrapped_tokens: [5][]u8 = undefined;
    
    for (wrapped_tokens, 0..) |*token, i| {
        _ = i;
        token.* = try paserk.wrapLocalKeyWithLocalKey(allocator, &local_key, &wrapping_key);
    }
    defer {
        for (wrapped_tokens) |token| {
            allocator.free(token);
        }
    }
    
    // All should unwrap to the same original key
    for (wrapped_tokens) |token| {
        const unwrapped = try paserk.unwrapLocalKeyWithLocalKey(allocator, token, &wrapping_key);
        try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
    }
}

test "wrapping with same wrapping key different target keys" {
    const allocator = testing.allocator;
    
    var wrapping_key = v4.LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Create different target keys
    var keys: [3]v4.LocalKey = undefined;
    for (keys, 0..) |*key, i| {
        var seed: [32]u8 = undefined;
        @memset(&seed, @intCast(i + 1));
        key.* = try v4.LocalKey.fromBytes(&seed);
    }
    
    // Wrap all keys with same wrapping key
    var wrapped: [3][]u8 = undefined;
    for (keys, 0..) |*key, i| {
        wrapped[i] = try paserk.wrapLocalKeyWithLocalKey(allocator, key, &wrapping_key);
    }
    defer {
        for (wrapped) |w| {
            allocator.free(w);
        }
    }
    
    // All wrapped keys should be different
    for (wrapped, 0..) |w1, i| {
        for (wrapped[i + 1..], i + 1..) |w2, j| {
            _ = j;
            try testing.expect(!mem.eql(u8, w1, w2));
        }
    }
    
    // But should unwrap to correct original keys
    for (wrapped, 0..) |w, i| {
        const unwrapped = try paserk.unwrapLocalKeyWithLocalKey(allocator, w, &wrapping_key);
        try testing.expectEqualSlices(u8, keys[i].bytes(), unwrapped.bytes());
    }
}