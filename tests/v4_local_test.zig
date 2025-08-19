const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const errors = @import("../src/errors.zig");

test "v4.local basic encrypt/decrypt" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "Hello, PASETO!";
    
    const token = try v4.encryptLocal(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local empty payload" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try v4.encryptLocal(allocator, "", &key, null, null);
    defer allocator.free(token);
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings("", decrypted);
}

test "v4.local large payload" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Create large payload (10KB)
    const large_payload = try allocator.alloc(u8, 10240);
    defer allocator.free(large_payload);
    
    for (large_payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    
    const token = try v4.encryptLocal(allocator, large_payload, &key, null, null);
    defer allocator.free(token);
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualSlices(u8, large_payload, decrypted);
}

test "v4.local binary payload" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const binary_payload = [_]u8{ 0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x02, 0xFD };
    
    const token = try v4.encryptLocal(allocator, &binary_payload, &key, null, null);
    defer allocator.free(token);
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualSlices(u8, &binary_payload, decrypted);
}

test "v4.local with footer" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "test payload";
    const footer = "test footer";
    
    const token = try v4.encryptLocal(allocator, payload, &key, footer, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.local."));
    try testing.expect(mem.endsWith(u8, token, footer));
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, footer, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local with empty footer" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "test payload";
    
    const token = try v4.encryptLocal(allocator, payload, &key, "", null);
    defer allocator.free(token);
    
    try testing.expect(mem.endsWith(u8, token, "."));
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, "", null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local with implicit assertion" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "secret message";
    const implicit = "context-specific-data";
    
    const token = try v4.encryptLocal(allocator, payload, &key, null, implicit);
    defer allocator.free(token);
    
    // Should decrypt with correct implicit
    const decrypted = try v4.decryptLocal(allocator, token, &key, null, implicit);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        v4.decryptLocal(allocator, token, &key, null, "wrong-implicit"));
    
    // Should fail with no implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        v4.decryptLocal(allocator, token, &key, null, null));
}

test "v4.local with footer and implicit" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "combined test";
    const footer = "public footer";
    const implicit = "private context";
    
    const token = try v4.encryptLocal(allocator, payload, &key, footer, implicit);
    defer allocator.free(token);
    
    const decrypted = try v4.decryptLocal(allocator, token, &key, footer, implicit);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
    
    // Should fail with mismatched footer
    try testing.expectError(errors.Error.InvalidFooter,
        v4.decryptLocal(allocator, token, &key, "wrong footer", implicit));
    
    // Should fail with mismatched implicit
    try testing.expectError(errors.Error.InvalidSignature,
        v4.decryptLocal(allocator, token, &key, footer, "wrong implicit"));
}

test "v4.local wrong key fails" {
    const allocator = testing.allocator;
    
    var key1 = v4.LocalKey.generate();
    defer key1.deinit();
    
    var key2 = v4.LocalKey.generate();
    defer key2.deinit();
    
    const payload = "encrypted with key1";
    
    const token = try v4.encryptLocal(allocator, payload, &key1, null, null);
    defer allocator.free(token);
    
    // Should fail to decrypt with wrong key
    try testing.expectError(errors.Error.InvalidSignature,
        v4.decryptLocal(allocator, token, &key2, null, null));
}

test "v4.local deterministic with same nonce" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "deterministic test";
    const nonce = [_]u8{0x42} ** 32;
    
    const token1 = try v4.local.encryptWithNonce(allocator, payload, &key, &nonce, null, null);
    defer allocator.free(token1);
    
    const token2 = try v4.local.encryptWithNonce(allocator, payload, &key, &nonce, null, null);
    defer allocator.free(token2);
    
    // Same key, payload, and nonce should produce identical tokens
    try testing.expectEqualStrings(token1, token2);
}

test "v4.local non-deterministic with random nonce" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "random test";
    
    const token1 = try v4.encryptLocal(allocator, payload, &key, null, null);
    defer allocator.free(token1);
    
    const token2 = try v4.encryptLocal(allocator, payload, &key, null, null);
    defer allocator.free(token2);
    
    // Random nonces should produce different tokens
    try testing.expect(!mem.eql(u8, token1, token2));
    
    // But both should decrypt to same payload
    const decrypted1 = try v4.decryptLocal(allocator, token1, &key, null, null);
    defer allocator.free(decrypted1);
    
    const decrypted2 = try v4.decryptLocal(allocator, token2, &key, null, null);
    defer allocator.free(decrypted2);
    
    try testing.expectEqualStrings(payload, decrypted1);
    try testing.expectEqualStrings(payload, decrypted2);
}

test "v4.local invalid token format" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // Wrong header
    try testing.expectError(errors.Error.InvalidHeader,
        v4.decryptLocal(allocator, "v3.local.invalidtoken", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        v4.decryptLocal(allocator, "v4.public.invalidtoken", &key, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        v4.decryptLocal(allocator, "invalid.header", &key, null, null));
    
    // Too short
    try testing.expectError(errors.Error.InvalidToken,
        v4.decryptLocal(allocator, "v4.local.AA", &key, null, null));
    
    // Empty token body
    try testing.expectError(error.InvalidCharacter,
        v4.decryptLocal(allocator, "v4.local.", &key, null, null));
}

test "v4.local corrupted token" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "test corruption";
    
    var token = try v4.encryptLocal(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    // Corrupt different parts of the token
    const original_token = try allocator.dupe(u8, token);
    defer allocator.free(original_token);
    
    // Corrupt middle of token (should be base64url data)
    if (token.len > 20) {
        token[15] = if (token[15] == 'A') 'B' else 'A';
        try testing.expectError(errors.Error.InvalidSignature,
            v4.decryptLocal(allocator, token, &key, null, null));
        
        // Restore token
        @memcpy(token, original_token);
    }
    
    // Corrupt end of token
    if (token.len > 10) {
        token[token.len - 5] = if (token[token.len - 5] == 'A') 'B' else 'A';
        try testing.expectError(errors.Error.InvalidSignature,
            v4.decryptLocal(allocator, token, &key, null, null));
    }
}

test "v4.local footer mismatch" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "footer test";
    const footer = "expected footer";
    
    const token = try v4.encryptLocal(allocator, payload, &key, footer, null);
    defer allocator.free(token);
    
    // Wrong footer
    try testing.expectError(errors.Error.InvalidFooter,
        v4.decryptLocal(allocator, token, &key, "wrong footer", null));
    
    // Missing footer when expected
    try testing.expectError(errors.Error.InvalidFooter,
        v4.decryptLocal(allocator, token, &key, null, null));
    
    // Extra footer when not expected
    const token_no_footer = try v4.encryptLocal(allocator, payload, &key, null, null);
    defer allocator.free(token_no_footer);
    
    try testing.expectError(errors.Error.InvalidFooter,
        v4.decryptLocal(allocator, token_no_footer, &key, "unexpected", null));
}

test "v4.local special payloads" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    // JSON payload
    const json_payload = "{\\"key\\": \\"value\\", \\"number\\": 42}";
    const token_json = try v4.encryptLocal(allocator, json_payload, &key, null, null);
    defer allocator.free(token_json);
    
    const decrypted_json = try v4.decryptLocal(allocator, token_json, &key, null, null);
    defer allocator.free(decrypted_json);
    
    try testing.expectEqualStrings(json_payload, decrypted_json);
    
    // Unicode payload
    const unicode_payload = "Hello 🌍 World! こんにちは";
    const token_unicode = try v4.encryptLocal(allocator, unicode_payload, &key, null, null);
    defer allocator.free(token_unicode);
    
    const decrypted_unicode = try v4.decryptLocal(allocator, token_unicode, &key, null, null);
    defer allocator.free(decrypted_unicode);
    
    try testing.expectEqualStrings(unicode_payload, decrypted_unicode);
    
    // Very long string
    const long_string = "A" ** 1000;
    const token_long = try v4.encryptLocal(allocator, long_string, &key, null, null);
    defer allocator.free(token_long);
    
    const decrypted_long = try v4.decryptLocal(allocator, token_long, &key, null, null);
    defer allocator.free(decrypted_long);
    
    try testing.expectEqualStrings(long_string, decrypted_long);
}

test "v4.local token structure validation" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const token = try v4.encryptLocal(allocator, "test", &key, "footer", null);
    defer allocator.free(token);
    
    // Token should have correct structure: v4.local.<data>.footer
    const parts = mem.split(u8, token, ".");
    var part_count: usize = 0;
    var iterator = parts;
    
    while (iterator.next()) |_| {
        part_count += 1;
    }
    
    try testing.expectEqual(@as(usize, 4), part_count); // v4, local, data, footer
    
    // First two parts should be "v4" and "local"
    var iterator2 = mem.split(u8, token, ".");
    try testing.expectEqualStrings("v4", iterator2.next().?);
    try testing.expectEqualStrings("local", iterator2.next().?);
    
    const data_part = iterator2.next().?;
    try testing.expect(data_part.len > 0);
    
    const footer_part = iterator2.next().?;
    try testing.expectEqualStrings("footer", footer_part);
}

test "v4.local nonce uniqueness" {
    const allocator = testing.allocator;
    
    var key = v4.LocalKey.generate();
    defer key.deinit();
    
    const payload = "nonce test";
    var tokens = std.ArrayList([]u8).init(allocator);
    defer {
        for (tokens.items) |token| {
            allocator.free(token);
        }
        tokens.deinit();
    }
    
    // Generate multiple tokens with same key and payload
    for (0..10) |_| {
        const token = try v4.encryptLocal(allocator, payload, &key, null, null);
        try tokens.append(token);
    }
    
    // All tokens should be different (due to random nonces)
    for (tokens.items, 0..) |token1, i| {
        for (tokens.items[i + 1..]) |token2| {
            try testing.expect(!mem.eql(u8, token1, token2));
        }
    }
    
    // But all should decrypt to the same payload
    for (tokens.items) |token| {
        const decrypted = try v4.decryptLocal(allocator, token, &key, null, null);
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(payload, decrypted);
    }
}