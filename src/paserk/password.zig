const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const types = @import("types.zig");
const v4 = @import("../v4/mod.zig");

const PaserkHeader = types.PaserkHeader;
const LocalKey = v4.LocalKey;
const SecretKey = v4.SecretKey;

/// Password-based key derivation parameters
pub const PbkdfParams = struct {
    iterations: u32 = 100000,  // PBKDF2 iterations
    salt_len: usize = 16,      // Salt length in bytes
    
    const Self = @This();
    
    /// Serialize parameters to bytes
    pub fn serialize(self: Self) [8]u8 {
        var result: [8]u8 = undefined;
        std.mem.writeInt(u32, result[0..4][0..4], self.iterations, .little);
        std.mem.writeInt(u32, result[4..8][0..4], @intCast(self.salt_len), .little);
        return result;
    }
    
    /// Deserialize parameters from bytes
    pub fn deserialize(data: []const u8) !Self {
        if (data.len < 8) return errors.Error.InvalidToken;
        
        const iterations = std.mem.readInt(u32, data[0..4], .little);
        const salt_len = std.mem.readInt(u32, data[4..8], .little);
        
        if (salt_len > 64) return errors.Error.InvalidToken; // Reasonable limit
        
        return Self{
            .iterations = iterations,
            .salt_len = @intCast(salt_len),
        };
    }
};

/// Wrap a local key with a password
pub fn wrapLocalKeyWithPassword(
    allocator: Allocator,
    key_to_wrap: *const LocalKey,
    password: []const u8,
    params: PbkdfParams,
) ![]u8 {
    // Generate random salt
    const salt = try allocator.alloc(u8, params.salt_len);
    defer allocator.free(salt);
    std.crypto.random.bytes(salt);
    
    // Derive wrapping key from password
    var wrapping_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &wrapping_key,
        password,
        salt,
        params.iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    defer utils.secureZero(&wrapping_key);
    
    // Generate random nonce
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Encrypt the key
    var ciphertext: [32 + 16]u8 = undefined; // key + tag
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext[0..32],
        ciphertext[32..],
        key_to_wrap.bytes(),
        "", // no additional data
        nonce[0..12].*,
        wrapping_key,
    );
    
    // Build wrapped data: params + salt + nonce + ciphertext
    const wrapped_len = 8 + params.salt_len + 24 + 48; // params + salt + nonce + ciphertext
    var wrapped_data = try allocator.alloc(u8, wrapped_len);
    defer allocator.free(wrapped_data);
    
    var pos: usize = 0;
    const params_bytes = params.serialize();
    @memcpy(wrapped_data[pos..pos + 8], &params_bytes);
    pos += 8;
    
    @memcpy(wrapped_data[pos..pos + params.salt_len], salt);
    pos += params.salt_len;
    
    @memcpy(wrapped_data[pos..pos + 24], &nonce);
    pos += 24;
    
    @memcpy(wrapped_data[pos..], &ciphertext);
    
    // Create PASERK
    const header = PaserkHeader{ .version = 4, .type = .local_pw };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_data = try utils.base64urlEncode(allocator, wrapped_data);
    defer allocator.free(encoded_data);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
}

/// Unwrap a local key with a password
pub fn unwrapLocalKeyWithPassword(
    allocator: Allocator,
    paserk: []const u8,
    password: []const u8,
) !LocalKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .local_pw) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.local-pw.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    if (decoded.len < 8 + 16 + 24 + 48) { // min: params + min_salt + nonce + ciphertext
        return errors.Error.InvalidToken;
    }
    
    // Parse parameters
    const params = try PbkdfParams.deserialize(decoded[0..8]);
    var pos: usize = 8;
    
    // Extract salt
    if (pos + params.salt_len > decoded.len) return errors.Error.InvalidToken;
    const salt = decoded[pos..pos + params.salt_len];
    pos += params.salt_len;
    
    // Extract nonce
    if (pos + 24 > decoded.len) return errors.Error.InvalidToken;
    const nonce = decoded[pos..pos + 24];
    pos += 24;
    
    // Extract ciphertext
    if (pos + 48 > decoded.len) return errors.Error.InvalidToken;
    const ciphertext = decoded[pos..pos + 32];
    const tag = decoded[pos + 32..pos + 48];
    
    // Derive wrapping key from password
    var wrapping_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &wrapping_key,
        password,
        salt,
        params.iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    defer utils.secureZero(&wrapping_key);
    
    // Decrypt
    var plaintext: [32]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext,
        tag[0..16].*,
        "", // no additional data
        nonce[0..12].*,
        wrapping_key,
    ) catch return errors.Error.CryptographicFailure;
    
    return LocalKey.fromBytes(&plaintext);
}

/// Wrap a secret key with a password
pub fn wrapSecretKeyWithPassword(
    allocator: Allocator,
    key_to_wrap: *const SecretKey,
    password: []const u8,
    params: PbkdfParams,
) ![]u8 {
    // Generate random salt
    const salt = try allocator.alloc(u8, params.salt_len);
    defer allocator.free(salt);
    std.crypto.random.bytes(salt);
    
    // Derive wrapping key from password
    var wrapping_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &wrapping_key,
        password,
        salt,
        params.iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    defer utils.secureZero(&wrapping_key);
    
    // Generate random nonce
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Encrypt the seed
    var ciphertext: [32 + 16]u8 = undefined; // seed + tag
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext[0..32],
        ciphertext[32..],
        key_to_wrap.seed(),
        "", // no additional data
        nonce[0..12].*,
        wrapping_key,
    );
    
    // Build wrapped data: params + salt + nonce + ciphertext
    const wrapped_len = 8 + params.salt_len + 24 + 48;
    var wrapped_data = try allocator.alloc(u8, wrapped_len);
    defer allocator.free(wrapped_data);
    
    var pos: usize = 0;
    const params_bytes = params.serialize();
    @memcpy(wrapped_data[pos..pos + 8], &params_bytes);
    pos += 8;
    
    @memcpy(wrapped_data[pos..pos + params.salt_len], salt);
    pos += params.salt_len;
    
    @memcpy(wrapped_data[pos..pos + 24], &nonce);
    pos += 24;
    
    @memcpy(wrapped_data[pos..], &ciphertext);
    
    // Create PASERK
    const header = PaserkHeader{ .version = 4, .type = .secret_pw };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_data = try utils.base64urlEncode(allocator, wrapped_data);
    defer allocator.free(encoded_data);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
}

/// Unwrap a secret key with a password
pub fn unwrapSecretKeyWithPassword(
    allocator: Allocator,
    paserk: []const u8,
    password: []const u8,
) !SecretKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .secret_pw) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.secret-pw.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    if (decoded.len < 8 + 16 + 24 + 48) {
        return errors.Error.InvalidToken;
    }
    
    // Parse parameters
    const params = try PbkdfParams.deserialize(decoded[0..8]);
    var pos: usize = 8;
    
    // Extract salt
    if (pos + params.salt_len > decoded.len) return errors.Error.InvalidToken;
    const salt = decoded[pos..pos + params.salt_len];
    pos += params.salt_len;
    
    // Extract nonce
    if (pos + 24 > decoded.len) return errors.Error.InvalidToken;
    const nonce = decoded[pos..pos + 24];
    pos += 24;
    
    // Extract ciphertext
    if (pos + 48 > decoded.len) return errors.Error.InvalidToken;
    const ciphertext = decoded[pos..pos + 32];
    const tag = decoded[pos + 32..pos + 48];
    
    // Derive wrapping key from password
    var wrapping_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &wrapping_key,
        password,
        salt,
        params.iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    defer utils.secureZero(&wrapping_key);
    
    // Decrypt
    var plaintext: [32]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext,
        tag[0..16].*,
        "", // no additional data
        nonce[0..12].*,
        wrapping_key,
    ) catch return errors.Error.CryptographicFailure;
    
    return SecretKey.fromSeed(&plaintext);
}

test "local key password wrapping" {
    const allocator = testing.allocator;
    
    var key_to_wrap = LocalKey.generate();
    defer key_to_wrap.deinit();
    
    const password = "strong-password-123";
    const params = PbkdfParams{ .iterations = 1000 }; // Lower for testing speed
    
    // Wrap
    const wrapped = try wrapLocalKeyWithPassword(allocator, &key_to_wrap, password, params);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.local-pw."));
    
    // Unwrap
    const unwrapped = try unwrapLocalKeyWithPassword(allocator, wrapped, password);
    
    // Verify
    try testing.expectEqualSlices(u8, key_to_wrap.bytes(), unwrapped.bytes());
    
    // Should fail with wrong password
    try testing.expectError(errors.Error.CryptographicFailure,
        unwrapLocalKeyWithPassword(allocator, wrapped, "wrong-password"));
}

test "secret key password wrapping" {
    const allocator = testing.allocator;
    
    var key_pair = v4.KeyPair.generate();
    defer key_pair.deinit();
    
    const password = "another-strong-password";
    const params = PbkdfParams{ .iterations = 1000 };
    
    // Wrap
    const wrapped = try wrapSecretKeyWithPassword(allocator, &key_pair.secret, password, params);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.secret-pw."));
    
    // Unwrap
    const unwrapped = try unwrapSecretKeyWithPassword(allocator, wrapped, password);
    
    // Verify seeds match
    try testing.expectEqualSlices(u8, key_pair.secret.seed(), unwrapped.seed());
}