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

/// Wrap a local key with another local key
pub fn wrapLocalKey(
    allocator: Allocator,
    key_to_wrap: *const LocalKey,
    wrapping_key: *const LocalKey,
) ![]u8 {
    // Generate random nonce
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Encrypt the key using ChaCha20-Poly1305 (simplified)
    var ciphertext: [32 + 16]u8 = undefined; // key + tag
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext[0..32],
        ciphertext[32..],
        key_to_wrap.bytes(),
        "", // no additional data
        nonce[0..12].*,
        wrapping_key.bytes().*,
    );
    
    // Build wrapped data: nonce + ciphertext
    var wrapped_data: [24 + 32 + 16]u8 = undefined;
    @memcpy(wrapped_data[0..24], &nonce);
    @memcpy(wrapped_data[24..], &ciphertext);
    
    // Create PASERK
    const header = PaserkHeader{ .version = 4, .type = .local_wrap };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_data = try utils.base64urlEncode(allocator, &wrapped_data);
    defer allocator.free(encoded_data);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
}

/// Unwrap a local key
pub fn unwrapLocalKey(
    allocator: Allocator,
    paserk: []const u8,
    wrapping_key: *const LocalKey,
) !LocalKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .local_wrap) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.local-wrap.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    if (decoded.len != 24 + 32 + 16) {
        return errors.Error.InvalidToken;
    }
    
    const nonce = decoded[0..24];
    const ciphertext = decoded[24..56];
    const tag = decoded[56..72];
    
    // Decrypt
    var plaintext: [32]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext,
        tag.*,
        "", // no additional data
        nonce[0..12].*,
        wrapping_key.bytes().*,
    ) catch return errors.Error.CryptographicFailure;
    
    return LocalKey.fromBytes(&plaintext);
}

/// Wrap a secret key with a local key
pub fn wrapSecretKey(
    allocator: Allocator,
    key_to_wrap: *const SecretKey,
    wrapping_key: *const LocalKey,
) ![]u8 {
    // Generate random nonce
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Encrypt the seed using ChaCha20-Poly1305 (simplified)
    var ciphertext: [32 + 16]u8 = undefined; // seed + tag
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext[0..32],
        ciphertext[32..],
        key_to_wrap.seed(),
        "", // no additional data
        nonce[0..12].*,
        wrapping_key.bytes().*,
    );
    
    // Build wrapped data: nonce + ciphertext
    var wrapped_data: [24 + 32 + 16]u8 = undefined;
    @memcpy(wrapped_data[0..24], &nonce);
    @memcpy(wrapped_data[24..], &ciphertext);
    
    // Create PASERK
    const header = PaserkHeader{ .version = 4, .type = .secret_wrap };
    const header_str = try header.format(allocator);
    defer allocator.free(header_str);
    
    const encoded_data = try utils.base64urlEncode(allocator, &wrapped_data);
    defer allocator.free(encoded_data);
    
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ header_str, encoded_data });
}

/// Unwrap a secret key
pub fn unwrapSecretKey(
    allocator: Allocator,
    paserk: []const u8,
    wrapping_key: *const LocalKey,
) !SecretKey {
    const header = try PaserkHeader.parse(paserk);
    if (header.version != 4 or header.type != .secret_wrap) {
        return errors.Error.InvalidPaserkType;
    }
    
    const prefix = "k4.secret-wrap.";
    if (!mem.startsWith(u8, paserk, prefix)) {
        return errors.Error.InvalidPaserkFormat;
    }
    
    const data = paserk[prefix.len..];
    const decoded = try utils.base64urlDecode(allocator, data);
    defer allocator.free(decoded);
    
    if (decoded.len != 24 + 32 + 16) {
        return errors.Error.InvalidToken;
    }
    
    const nonce = decoded[0..24];
    const ciphertext = decoded[24..56];
    const tag = decoded[56..72];
    
    // Decrypt
    var plaintext: [32]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        &plaintext,
        ciphertext,
        tag.*,
        "", // no additional data
        nonce[0..12].*,
        wrapping_key.bytes().*,
    ) catch return errors.Error.CryptographicFailure;
    
    return SecretKey.fromSeed(&plaintext);
}

test "local key wrapping" {
    const allocator = testing.allocator;
    
    var key_to_wrap = LocalKey.generate();
    defer key_to_wrap.deinit();
    
    var wrapping_key = LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap
    const wrapped = try wrapLocalKey(allocator, &key_to_wrap, &wrapping_key);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.local-wrap."));
    
    // Unwrap
    const unwrapped = try unwrapLocalKey(allocator, wrapped, &wrapping_key);
    
    // Verify
    try testing.expectEqualSlices(u8, key_to_wrap.bytes(), unwrapped.bytes());
}

test "secret key wrapping" {
    const allocator = testing.allocator;
    
    var key_pair = v4.KeyPair.generate();
    defer key_pair.deinit();
    
    var wrapping_key = LocalKey.generate();
    defer wrapping_key.deinit();
    
    // Wrap
    const wrapped = try wrapSecretKey(allocator, &key_pair.secret, &wrapping_key);
    defer allocator.free(wrapped);
    
    try testing.expect(mem.startsWith(u8, wrapped, "k4.secret-wrap."));
    
    // Unwrap
    const unwrapped = try unwrapSecretKey(allocator, wrapped, &wrapping_key);
    
    // Verify seeds match
    try testing.expectEqualSlices(u8, key_pair.secret.seed(), unwrapped.seed());
}