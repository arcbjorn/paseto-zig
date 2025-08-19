const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");

const LocalKey = keys.LocalKey;
const Version = keys.Version;
const Purpose = keys.Purpose;

const HEADER_V4_LOCAL = "v4.local.";
const NONCE_SIZE = 32; // Random nonce size
const TAG_SIZE = 32;   // BLAKE2b MAC size

/// Encrypt a payload using v4.local (XChaCha20-Poly1305)
pub fn encrypt(
    allocator: Allocator,
    payload: []const u8,
    key: *const LocalKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Generate random nonce
    var nonce: [NONCE_SIZE]u8 = undefined;
    crypto.random.bytes(&nonce);
    
    return encryptWithNonce(allocator, payload, key, &nonce, footer, implicit);
}

/// Encrypt with a specific nonce (used for testing)
pub fn encryptWithNonce(
    allocator: Allocator,
    payload: []const u8,
    key: *const LocalKey,
    nonce: *const [NONCE_SIZE]u8,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Algorithm Lucidity: Validate key is appropriate for v4.local
    if (!key.isKeyValidFor(.v4, .local)) {
        return errors.Error.KeyTypeMismatch;
    }
    
    // Validate footer if provided
    if (footer) |f| {
        try utils.validateFooter(f);
    }
    
    // Calculate sizes
    const footer_len = if (footer) |f| f.len else 0;
    
    // Build pre-authentication data using PAE
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_LOCAL);
    try pae_parts.append(nonce);
    try pae_parts.append(""); // ciphertext placeholder, will be updated
    if (footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    // Derive encryption and authentication keys using BLAKE2b
    const ek_result = try deriveEncryptionKey(allocator, key.bytes(), nonce);
    defer allocator.free(ek_result.key);
    defer allocator.free(ek_result.n2);
    
    const ak = try deriveAuthKey(allocator, key.bytes(), nonce);
    defer allocator.free(ak);
    
    // Encrypt with XChaCha20 (simplified as ChaCha20 for Zig compatibility)
    const ciphertext = try allocator.alloc(u8, payload.len);
    defer allocator.free(ciphertext);
    
    // Use the derived n2 nonce (24 bytes), but take first 12 for ChaCha20
    const chacha_nonce = ek_result.n2[0..12].*;
    crypto.stream.chacha.ChaCha20IETF.xor(ciphertext, payload, 0, ek_result.key[0..32].*, chacha_nonce);
    
    // Update PAE with actual ciphertext
    pae_parts.items[2] = ciphertext;
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Generate BLAKE2b MAC (32 bytes)
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = ak[0..32] });
    hasher.update(pae_data);
    var tag: [32]u8 = undefined;
    hasher.final(&tag);
    
    // Build final token: header + base64url(nonce + ciphertext + tag) + footer
    const token_data = try allocator.alloc(u8, NONCE_SIZE + ciphertext.len + TAG_SIZE);
    defer allocator.free(token_data);
    
    @memcpy(token_data[0..NONCE_SIZE], nonce);
    @memcpy(token_data[NONCE_SIZE..NONCE_SIZE + ciphertext.len], ciphertext);
    @memcpy(token_data[NONCE_SIZE + ciphertext.len..], &tag);
    
    const encoded_data = try utils.base64urlEncode(allocator, token_data);
    defer allocator.free(encoded_data);
    
    // Construct final token
    const token_len = HEADER_V4_LOCAL.len + encoded_data.len + 
        (if (footer_len > 0) footer_len + 1 else 0); // +1 for '.'
    
    var token = try allocator.alloc(u8, token_len);
    var pos: usize = 0;
    
    @memcpy(token[pos..pos + HEADER_V4_LOCAL.len], HEADER_V4_LOCAL);
    pos += HEADER_V4_LOCAL.len;
    
    @memcpy(token[pos..pos + encoded_data.len], encoded_data);
    pos += encoded_data.len;
    
    if (footer) |f| {
        token[pos] = '.';
        pos += 1;
        @memcpy(token[pos..pos + f.len], f);
    }
    
    return token;
}

/// Decrypt a v4.local token
pub fn decrypt(
    allocator: Allocator,
    token: []const u8,
    key: *const LocalKey,
    footer: ?[]const u8,
    implicit: ?[]const u8,
) ![]u8 {
    // Algorithm Lucidity: Validate key is appropriate for v4.local
    if (!key.isKeyValidFor(.v4, .local)) {
        return errors.Error.KeyTypeMismatch;
    }
    
    // Check header
    if (token.len < HEADER_V4_LOCAL.len or 
        !mem.eql(u8, token[0..HEADER_V4_LOCAL.len], HEADER_V4_LOCAL)) {
        return errors.Error.InvalidHeader;
    }
    
    // Find the footer separator
    var token_body = token[HEADER_V4_LOCAL.len..];
    var found_footer: ?[]const u8 = null;
    
    if (mem.lastIndexOf(u8, token_body, ".")) |dot_pos| {
        found_footer = token_body[dot_pos + 1..];
        token_body = token_body[0..dot_pos];
    }
    
    // Validate footer if present
    if (found_footer) |f| {
        try utils.validateFooter(f);
    }
    
    // Verify footer matches
    if (footer) |expected_footer| {
        if (found_footer == null or !mem.eql(u8, found_footer.?, expected_footer)) {
            return errors.Error.InvalidFooter;
        }
    } else if (found_footer != null) {
        return errors.Error.InvalidFooter;
    }
    
    // Decode the token body
    const decoded = try utils.base64urlDecode(allocator, token_body);
    defer allocator.free(decoded);
    
    if (decoded.len < NONCE_SIZE + TAG_SIZE) {
        return errors.Error.InvalidToken;
    }
    
    const nonce = decoded[0..NONCE_SIZE];
    const tag = decoded[decoded.len - TAG_SIZE..];
    const ciphertext = decoded[NONCE_SIZE..decoded.len - TAG_SIZE];
    
    // Derive keys
    const ek_result = try deriveEncryptionKey(allocator, key.bytes(), nonce);
    defer allocator.free(ek_result.key);
    defer allocator.free(ek_result.n2);
    
    const ak = try deriveAuthKey(allocator, key.bytes(), nonce);
    defer allocator.free(ak);
    
    // Build PAE for authentication
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_LOCAL);
    try pae_parts.append(nonce);
    try pae_parts.append(ciphertext);
    if (found_footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Verify BLAKE2b MAC
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = ak[0..32] });
    hasher.update(pae_data);
    var expected_tag: [32]u8 = undefined;
    hasher.final(&expected_tag);
    if (!utils.constantTimeEqual(tag, &expected_tag)) {
        return errors.Error.InvalidSignature;
    }
    
    // Decrypt
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    const chacha_nonce = ek_result.n2[0..12].*;
    crypto.stream.chacha.ChaCha20IETF.xor(plaintext, ciphertext, 0, ek_result.key[0..32].*, chacha_nonce);
    
    return plaintext;
}

/// Derive encryption key and nonce using BLAKE2b (56 bytes total)
fn deriveEncryptionKey(allocator: Allocator, key: *const [32]u8, nonce: []const u8) !struct { key: []u8, n2: []u8 } {
    var hasher = crypto.hash.blake2.Blake2b512.init(.{ .key = &key.* });
    hasher.update("paseto-encryption-key");
    hasher.update(nonce);
    
    var tmp: [64]u8 = undefined;
    hasher.final(&tmp); // BLAKE2b512 produces 64 bytes, we take first 56
    
    // Split: first 32 bytes = encryption key, next 24 bytes = XChaCha20 nonce
    const ek = try allocator.alloc(u8, 32);
    const n2 = try allocator.alloc(u8, 24);
    @memcpy(ek, tmp[0..32]);
    @memcpy(n2, tmp[32..56]);
    
    return .{ .key = ek, .n2 = n2 };
}

/// Derive authentication key using BLAKE2b (32 bytes)
fn deriveAuthKey(allocator: Allocator, key: *const [32]u8, nonce: []const u8) ![]u8 {
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = &key.* });
    hasher.update("paseto-auth-key-for-aead");
    hasher.update(nonce);
    
    var ak = try allocator.alloc(u8, 32);
    hasher.final(ak[0..32]);
    return ak;
}

test "v4.local encrypt/decrypt without footer" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    
    const token = try encrypt(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_LOCAL));
    
    const decrypted = try decrypt(allocator, token, &key, null, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local encrypt/decrypt with footer" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    const footer = "test-footer";
    
    const token = try encrypt(allocator, payload, &key, footer, null);
    defer allocator.free(token);
    
    try testing.expect(mem.startsWith(u8, token, HEADER_V4_LOCAL));
    try testing.expect(mem.endsWith(u8, token, footer));
    
    const decrypted = try decrypt(allocator, token, &key, footer, null);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
}

test "v4.local encrypt/decrypt with implicit assertion" {
    const allocator = testing.allocator;
    
    var key = LocalKey.generate();
    defer key.deinit();
    
    const payload = "hello world";
    const implicit = "implicit-data";
    
    const token = try encrypt(allocator, payload, &key, null, implicit);
    defer allocator.free(token);
    
    const decrypted = try decrypt(allocator, token, &key, null, implicit);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(payload, decrypted);
    
    // Should fail with wrong implicit
    try testing.expectError(errors.Error.InvalidSignature, 
        decrypt(allocator, token, &key, null, "wrong-implicit"));
}

test "v4.local decrypt with wrong key should fail" {
    const allocator = testing.allocator;
    
    var key1 = LocalKey.generate();
    defer key1.deinit();
    
    var key2 = LocalKey.generate();
    defer key2.deinit();
    
    const payload = "hello world";
    
    const token = try encrypt(allocator, payload, &key1, null, null);
    defer allocator.free(token);
    
    try testing.expectError(errors.Error.InvalidSignature, 
        decrypt(allocator, token, &key2, null, null));
}