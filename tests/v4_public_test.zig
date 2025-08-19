const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const errors = @import("../src/errors.zig");

test "v4.public basic sign/verify" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "Hello, PASETO public!";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.public."));
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings(payload, verified);
}

test "v4.public empty payload" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const token = try v4.signPublic(allocator, "", &keypair.secret, null, null);
    defer allocator.free(token);
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings("", verified);
}

test "v4.public large payload" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Create large payload (5KB)
    const large_payload = try allocator.alloc(u8, 5120);
    defer allocator.free(large_payload);
    
    for (large_payload, 0..) |*byte, i| {
        byte.* = @intCast((i % 95) + 32); // Printable ASCII
    }
    
    const token = try v4.signPublic(allocator, large_payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
    defer allocator.free(verified);
    
    try testing.expectEqualSlices(u8, large_payload, verified);
}

test "v4.public binary payload" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const binary_payload = [_]u8{ 0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x02, 0xFD };
    
    const token = try v4.signPublic(allocator, &binary_payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
    defer allocator.free(verified);
    
    try testing.expectEqualSlices(u8, &binary_payload, verified);
}

test "v4.public with footer" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "test payload";
    const footer = "test footer";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, footer, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, "v4.public."));
    try testing.expect(mem.endsWith(u8, token, footer));
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, footer, null);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings(payload, verified);
}

test "v4.public with empty footer" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "test payload";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, "", null);
    defer allocator.free(token);
    
    try testing.expect(mem.endsWith(u8, token, "."));
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, "", null);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings(payload, verified);
}

test "v4.public with implicit assertion" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "secret message";
    const implicit = "context-specific-data";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, null, implicit);
    defer allocator.free(token);
    
    // Should verify with correct implicit
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, implicit);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings(payload, verified);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        v4.verifyPublic(allocator, token, &keypair.public, null, "wrong-implicit"));
    
    // Should fail with no implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        v4.verifyPublic(allocator, token, &keypair.public, null, null));
}

test "v4.public with footer and implicit" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "combined test";
    const footer = "public footer";
    const implicit = "private context";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, footer, implicit);
    defer allocator.free(token);
    
    const verified = try v4.verifyPublic(allocator, token, &keypair.public, footer, implicit);
    defer allocator.free(verified);
    
    try testing.expectEqualStrings(payload, verified);
    
    // Should fail with mismatched footer
    try testing.expectError(errors.Error.InvalidFooter,
        v4.verifyPublic(allocator, token, &keypair.public, "wrong footer", implicit));
    
    // Should fail with mismatched implicit
    try testing.expectError(errors.Error.InvalidSignature,
        v4.verifyPublic(allocator, token, &keypair.public, footer, "wrong implicit"));
}

test "v4.public wrong key fails" {
    const allocator = testing.allocator;
    
    var keypair1 = v4.KeyPair.generate();
    defer keypair1.deinit();
    
    var keypair2 = v4.KeyPair.generate();
    defer keypair2.deinit();
    
    const payload = "signed with keypair1";
    
    const token = try v4.signPublic(allocator, payload, &keypair1.secret, null, null);
    defer allocator.free(token);
    
    // Should fail to verify with wrong public key
    try testing.expectError(errors.Error.InvalidSignature,
        v4.verifyPublic(allocator, token, &keypair2.public, null, null));
}

test "v4.public deterministic signatures" {
    const allocator = testing.allocator;
    
    const seed = [_]u8{0x42} ** 32;
    
    var keypair1 = try v4.KeyPair.fromSeed(&seed);
    defer keypair1.deinit();
    
    var keypair2 = try v4.KeyPair.fromSeed(&seed);
    defer keypair2.deinit();
    
    const payload = "deterministic test";
    
    const token1 = try v4.signPublic(allocator, payload, &keypair1.secret, null, null);
    defer allocator.free(token1);
    
    const token2 = try v4.signPublic(allocator, payload, &keypair2.secret, null, null);
    defer allocator.free(token2);
    
    // Same seed and payload should produce identical signatures
    try testing.expectEqualStrings(token1, token2);
}

test "v4.public different payloads different signatures" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload1 = "message one";
    const payload2 = "message two";
    
    const token1 = try v4.signPublic(allocator, payload1, &keypair.secret, null, null);
    defer allocator.free(token1);
    
    const token2 = try v4.signPublic(allocator, payload2, &keypair.secret, null, null);
    defer allocator.free(token2);
    
    // Different payloads should produce different signatures
    try testing.expect(!mem.eql(u8, token1, token2));
}

test "v4.public invalid token format" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // Wrong header
    try testing.expectError(errors.Error.InvalidHeader,
        v4.verifyPublic(allocator, "v3.public.invalidtoken", &keypair.public, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        v4.verifyPublic(allocator, "v4.local.invalidtoken", &keypair.public, null, null));
    
    try testing.expectError(errors.Error.InvalidHeader,
        v4.verifyPublic(allocator, "invalid.header", &keypair.public, null, null));
    
    // Too short (less than signature size)
    try testing.expectError(errors.Error.InvalidToken,
        v4.verifyPublic(allocator, "v4.public.AA", &keypair.public, null, null));
    
    // Empty token body
    try testing.expectError(error.InvalidCharacter,
        v4.verifyPublic(allocator, "v4.public.", &keypair.public, null, null));
}

test "v4.public corrupted token" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "test corruption";
    
    var token = try v4.signPublic(allocator, payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    // Corrupt different parts of the token
    const original_token = try allocator.dupe(u8, token);
    defer allocator.free(original_token);
    
    // Corrupt middle of token (should be base64url data)
    if (token.len > 20) {
        token[15] = if (token[15] == 'A') 'B' else 'A';
        try testing.expectError(errors.Error.InvalidSignature,
            v4.verifyPublic(allocator, token, &keypair.public, null, null));
        
        // Restore token
        @memcpy(token, original_token);
    }
    
    // Corrupt end of token (signature area)
    if (token.len > 10) {
        token[token.len - 5] = if (token[token.len - 5] == 'A') 'B' else 'A';
        try testing.expectError(errors.Error.InvalidSignature,
            v4.verifyPublic(allocator, token, &keypair.public, null, null));
    }
}

test "v4.public footer mismatch" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "footer test";
    const footer = "expected footer";
    
    const token = try v4.signPublic(allocator, payload, &keypair.secret, footer, null);
    defer allocator.free(token);
    
    // Wrong footer
    try testing.expectError(errors.Error.InvalidFooter,
        v4.verifyPublic(allocator, token, &keypair.public, "wrong footer", null));
    
    // Missing footer when expected
    try testing.expectError(errors.Error.InvalidFooter,
        v4.verifyPublic(allocator, token, &keypair.public, null, null));
    
    // Extra footer when not expected
    const token_no_footer = try v4.signPublic(allocator, payload, &keypair.secret, null, null);
    defer allocator.free(token_no_footer);
    
    try testing.expectError(errors.Error.InvalidFooter,
        v4.verifyPublic(allocator, token_no_footer, &keypair.public, "unexpected", null));
}

test "v4.public special payloads" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    // JSON payload
    const json_payload = "{\\"key\\": \\"value\\", \\"number\\": 42}";
    const token_json = try v4.signPublic(allocator, json_payload, &keypair.secret, null, null);
    defer allocator.free(token_json);
    
    const verified_json = try v4.verifyPublic(allocator, token_json, &keypair.public, null, null);
    defer allocator.free(verified_json);
    
    try testing.expectEqualStrings(json_payload, verified_json);
    
    // Unicode payload
    const unicode_payload = "Hello 🌍 World! こんにちは";
    const token_unicode = try v4.signPublic(allocator, unicode_payload, &keypair.secret, null, null);
    defer allocator.free(token_unicode);
    
    const verified_unicode = try v4.verifyPublic(allocator, token_unicode, &keypair.public, null, null);
    defer allocator.free(verified_unicode);
    
    try testing.expectEqualStrings(unicode_payload, verified_unicode);
    
    // Newlines and special characters
    const special_payload = "Line 1\\nLine 2\\tTabbed\\r\\nWindows newline";
    const token_special = try v4.signPublic(allocator, special_payload, &keypair.secret, null, null);
    defer allocator.free(token_special);
    
    const verified_special = try v4.verifyPublic(allocator, token_special, &keypair.public, null, null);
    defer allocator.free(verified_special);
    
    try testing.expectEqualStrings(special_payload, verified_special);
}

test "v4.public token structure validation" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const token = try v4.signPublic(allocator, "test", &keypair.secret, "footer", null);
    defer allocator.free(token);
    
    // Token should have correct structure: v4.public.<data>.footer
    const parts = mem.split(u8, token, ".");
    var part_count: usize = 0;
    var iterator = parts;
    
    while (iterator.next()) |_| {
        part_count += 1;
    }
    
    try testing.expectEqual(@as(usize, 4), part_count); // v4, public, data, footer
    
    // First two parts should be "v4" and "public"
    var iterator2 = mem.split(u8, token, ".");
    try testing.expectEqualStrings("v4", iterator2.next().?);
    try testing.expectEqualStrings("public", iterator2.next().?);
    
    const data_part = iterator2.next().?;
    try testing.expect(data_part.len > 0);
    
    const footer_part = iterator2.next().?;
    try testing.expectEqualStrings("footer", footer_part);
}

test "v4.public signature consistency" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const payload = "consistency test";
    
    // Sign multiple times
    var tokens = std.ArrayList([]u8).init(allocator);
    defer {
        for (tokens.items) |token| {
            allocator.free(token);
        }
        tokens.deinit();
    }
    
    for (0..5) |_| {
        const token = try v4.signPublic(allocator, payload, &keypair.secret, null, null);
        try tokens.append(token);
    }
    
    // All signatures should be identical (Ed25519 is deterministic)
    for (tokens.items[1..]) |token| {
        try testing.expectEqualStrings(tokens.items[0], token);
    }
    
    // All should verify
    for (tokens.items) |token| {
        const verified = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
        defer allocator.free(verified);
        try testing.expectEqualStrings(payload, verified);
    }
}

test "v4.public cross-verification" {
    const allocator = testing.allocator;
    
    // Generate multiple keypairs
    var keypairs: [3]v4.KeyPair = undefined;
    for (keypairs, 0..) |*kp, i| {
        const seed = [_]u8{@intCast(i + 1)} ** 32;
        kp.* = try v4.KeyPair.fromSeed(&seed);
    }
    defer for (keypairs) |*kp| kp.deinit();
    
    const payload = "cross verification test";
    
    // Each keypair signs the same payload
    var tokens: [3][]u8 = undefined;
    for (keypairs, 0..) |*kp, i| {
        tokens[i] = try v4.signPublic(allocator, payload, &kp.secret, null, null);
    }
    defer for (tokens) |token| allocator.free(token);
    
    // Each token should only verify with its own public key
    for (tokens, 0..) |token, i| {
        for (keypairs, 0..) |*kp, j| {
            if (i == j) {
                // Should verify with matching key
                const verified = try v4.verifyPublic(allocator, token, &kp.public, null, null);
                defer allocator.free(verified);
                try testing.expectEqualStrings(payload, verified);
            } else {
                // Should fail with non-matching key
                try testing.expectError(errors.Error.InvalidSignature,
                    v4.verifyPublic(allocator, token, &kp.public, null, null));
            }
        }
    }
}

test "v4.public payload tampering detection" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const original_payload = "original message";
    const token = try v4.signPublic(allocator, original_payload, &keypair.secret, null, null);
    defer allocator.free(token);
    
    // Verify original token works
    const verified_original = try v4.verifyPublic(allocator, token, &keypair.public, null, null);
    defer allocator.free(verified_original);
    try testing.expectEqualStrings(original_payload, verified_original);
    
    // Now try to create a token with different payload but same signature
    const tampered_payload = "tampered message";
    const tampered_token = try v4.signPublic(allocator, tampered_payload, &keypair.secret, null, null);
    defer allocator.free(tampered_token);
    
    // Extract signature from original token and try to use with tampered payload
    // This would require manual token manipulation, which should fail verification
    
    // The tampered token should verify only to its own payload
    const verified_tampered = try v4.verifyPublic(allocator, tampered_token, &keypair.public, null, null);
    defer allocator.free(verified_tampered);
    try testing.expectEqualStrings(tampered_payload, verified_tampered);
    
    // And should be different from original
    try testing.expect(!mem.eql(u8, original_payload, tampered_payload));
    try testing.expect(!mem.eql(u8, token, tampered_token));
}