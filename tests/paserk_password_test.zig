const std = @import("std");
const testing = std.testing;
const mem = std.mem;

const v4 = @import("../src/v4/mod.zig");
const paserk = @import("../src/paserk/mod.zig");
const errors = @import("../src/errors.zig");

test "password wrap local key basic" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "test-password-123";
    const options = paserk.PasswordOptions{ .iterations = 1000 }; // Reduced for testing
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.local-pw."));
    
    // Unwrap and verify
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrap secret key basic" {
    const allocator = testing.allocator;
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const password = "secret-password-456";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapSecretKeyWithPassword(
        allocator, 
        &keypair.secret, 
        password, 
        options
    );
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.secret-pw."));
    
    const unwrapped = try paserk.password.unwrapSecretKeyWithPassword(
        allocator, 
        wrapped, 
        password
    );
    
    try testing.expectEqualSlices(u8, keypair.secret.bytes(), unwrapped.bytes());
}

test "password wrapping different iterations" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "test-password";
    
    // Test different iteration counts
    const iteration_counts = [_]u32{ 1000, 5000, 10000, 50000 };
    
    for (iteration_counts) |iterations| {
        const options = paserk.PasswordOptions{ .iterations = iterations };
        
        const wrapped = try paserk.password.wrapLocalKeyWithPassword(
            allocator, 
            &local_key, 
            password, 
            options
        );
        defer allocator.free(wrapped);
        
        const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
            allocator, 
            wrapped, 
            password
        );
        
        try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
    }
}

test "password wrapping deterministic with salt" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "deterministic-test";
    const salt = [_]u8{0x42} ** 16;
    const options = paserk.PasswordOptions{ 
        .iterations = 1000, 
        .salt = &salt 
    };
    
    const wrapped1 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped2);
    
    // Should be identical with same salt
    try testing.expectEqualStrings(wrapped1, wrapped2);
}

test "password wrapping random salt" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "random-salt-test";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped1 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped1);
    
    const wrapped2 = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped2);
    
    // Should be different with random salts
    try testing.expect(!mem.eql(u8, wrapped1, wrapped2));
    
    // But both should unwrap correctly
    const unwrapped1 = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped1, 
        password
    );
    const unwrapped2 = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped2, 
        password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped1.bytes());
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped2.bytes());
}

test "password wrapping wrong password fails" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const correct_password = "correct-password";
    const wrong_password = "wrong-password";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        correct_password, 
        options
    );
    defer allocator.free(wrapped);
    
    // Should fail with wrong password
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.password.unwrapLocalKeyWithPassword(allocator, wrapped, wrong_password));
}

test "password wrapping empty password" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const empty_password = "";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        empty_password, 
        options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        empty_password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
    
    // Should fail with non-empty password
    try testing.expectError(errors.Error.InvalidSignature,
        paserk.password.unwrapLocalKeyWithPassword(allocator, wrapped, "not-empty"));
}

test "password wrapping unicode password" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const unicode_password = "пароль🔐密码";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        unicode_password, 
        options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        unicode_password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping long password" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    // Very long password (1000 characters)
    const long_password = "a" ** 1000;
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        long_password, 
        options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        long_password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping special characters" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const special_password = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        special_password, 
        options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        special_password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping minimum iterations" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "test";
    
    // Test minimum allowed iterations
    const min_options = paserk.PasswordOptions{ .iterations = 1 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        min_options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping high iterations" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "high-iter-test";
    // High iteration count (but still reasonable for testing)
    const high_options = paserk.PasswordOptions{ .iterations = 100000 };
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        high_options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping format validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    var keypair = v4.KeyPair.generate();
    defer keypair.deinit();
    
    const password = "format-test";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    const local_wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(local_wrapped);
    
    const secret_wrapped = try paserk.password.wrapSecretKeyWithPassword(
        allocator, 
        &keypair.secret, 
        password, 
        options
    );
    defer allocator.free(secret_wrapped);
    
    // Verify correct headers
    try testing.expect(mem.startsWith(u8, local_wrapped, "k4.local-pw."));
    try testing.expect(mem.startsWith(u8, secret_wrapped, "k4.secret-pw."));
    
    // Should be base64url encoded (no padding, no + or /)
    const local_data = local_wrapped["k4.local-pw.".len..];
    const secret_data = secret_wrapped["k4.secret-pw.".len..];
    
    try testing.expect(mem.indexOf(u8, local_data, "=") == null);
    try testing.expect(mem.indexOf(u8, local_data, "+") == null);
    try testing.expect(mem.indexOf(u8, local_data, "/") == null);
    
    try testing.expect(mem.indexOf(u8, secret_data, "=") == null);
    try testing.expect(mem.indexOf(u8, secret_data, "+") == null);
    try testing.expect(mem.indexOf(u8, secret_data, "/") == null);
}

test "password wrapping invalid formats" {
    const allocator = testing.allocator;
    
    const password = "test-password";
    
    const invalid_formats = [_][]const u8{
        "k3.local-pw.dGVzdA", // Wrong version
        "k4.secret-pw.dGVzdA", // Wrong type for local unwrap
        "k4.local-pw.", // Empty data
        "k4.local-pw.invalid+base64", // Invalid base64url
        "k4.local-pw.dGVzdA", // Too short data
    };
    
    for (invalid_formats) |format| {
        const result = paserk.password.unwrapLocalKeyWithPassword(allocator, format, password);
        try testing.expect(std.meta.isError(result));
    }
}

test "password wrapping edge case keys" {
    const allocator = testing.allocator;
    
    const password = "edge-case-test";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    // Test edge case keys
    const zero_key = try v4.LocalKey.fromBytes(&([_]u8{0} ** 32));
    const max_key = try v4.LocalKey.fromBytes(&([_]u8{0xFF} ** 32));
    
    var pattern_bytes: [32]u8 = undefined;
    for (pattern_bytes, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    const pattern_key = try v4.LocalKey.fromBytes(&pattern_bytes);
    
    const test_keys = [_]v4.LocalKey{ zero_key, max_key, pattern_key };
    
    for (test_keys) |key| {
        const wrapped = try paserk.password.wrapLocalKeyWithPassword(
            allocator, 
            &key, 
            password, 
            options
        );
        defer allocator.free(wrapped);
        
        const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
            allocator, 
            wrapped, 
            password
        );
        
        try testing.expectEqualSlices(u8, key.bytes(), unwrapped.bytes());
    }
}

test "password wrapping corrupted data" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "corruption-test";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    var wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        options
    );
    defer allocator.free(wrapped);
    
    // Make a copy to corrupt
    var corrupted = try allocator.dupe(u8, wrapped);
    defer allocator.free(corrupted);
    
    // Corrupt in the middle
    if (corrupted.len > 20) {
        corrupted[15] = if (corrupted[15] == 'A') 'B' else 'A';
        
        try testing.expectError(errors.Error.InvalidSignature,
            paserk.password.unwrapLocalKeyWithPassword(allocator, corrupted, password));
    }
}

test "password options default values" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "default-test";
    
    // Use default options
    const default_options = paserk.PasswordOptions{};
    
    const wrapped = try paserk.password.wrapLocalKeyWithPassword(
        allocator, 
        &local_key, 
        password, 
        default_options
    );
    defer allocator.free(wrapped);
    
    const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
        allocator, 
        wrapped, 
        password
    );
    
    try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
}

test "password wrapping concurrent operations" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "concurrent-test";
    const options = paserk.PasswordOptions{ .iterations = 1000 };
    
    // Perform multiple wrap operations with same parameters
    var wrapped_tokens: [3][]u8 = undefined;
    
    for (wrapped_tokens, 0..) |*token, i| {
        _ = i;
        token.* = try paserk.password.wrapLocalKeyWithPassword(
            allocator, 
            &local_key, 
            password, 
            options
        );
    }
    defer {
        for (wrapped_tokens) |token| {
            allocator.free(token);
        }
    }
    
    // All should unwrap to the same original key
    for (wrapped_tokens) |token| {
        const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
            allocator, 
            token, 
            password
        );
        
        try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
    }
}

test "password wrapping salt size validation" {
    const allocator = testing.allocator;
    
    var local_key = v4.LocalKey.generate();
    defer local_key.deinit();
    
    const password = "salt-size-test";
    
    // Test with different salt sizes
    const salt_8 = [_]u8{0x11} ** 8;
    const salt_16 = [_]u8{0x22} ** 16;
    const salt_32 = [_]u8{0x33} ** 32;
    
    const options_8 = paserk.PasswordOptions{ .iterations = 1000, .salt = &salt_8 };
    const options_16 = paserk.PasswordOptions{ .iterations = 1000, .salt = &salt_16 };
    const options_32 = paserk.PasswordOptions{ .iterations = 1000, .salt = &salt_32 };
    
    const salts_and_options = [_]struct { 
        salt: []const u8, 
        options: paserk.PasswordOptions 
    }{
        .{ .salt = &salt_8, .options = options_8 },
        .{ .salt = &salt_16, .options = options_16 },
        .{ .salt = &salt_32, .options = options_32 },
    };
    
    for (salts_and_options) |item| {
        const wrapped = try paserk.password.wrapLocalKeyWithPassword(
            allocator, 
            &local_key, 
            password, 
            item.options
        );
        defer allocator.free(wrapped);
        
        const unwrapped = try paserk.password.unwrapLocalKeyWithPassword(
            allocator, 
            wrapped, 
            password
        );
        
        try testing.expectEqualSlices(u8, local_key.bytes(), unwrapped.bytes());
    }
}