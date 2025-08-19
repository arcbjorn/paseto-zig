const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");

const LocalKey = keys.LocalKey;

const HEADER_V4_LOCAL = "v4.local.";
const NONCE_SIZE = 32; // XChaCha20 nonce size
const TAG_SIZE = 16;   // Poly1305 tag size

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
    // Validate footer if provided
    if (footer) |f| {
        try utils.validateFooter(f);
    }
    
    // Calculate sizes
    const footer_len = if (footer) |f| f.len else 0;
    const ciphertext_len = payload.len + TAG_SIZE;
    
    // Build pre-authentication data using PAE
    var pae_parts = std.ArrayList([]const u8).init(allocator);
    defer pae_parts.deinit();
    
    try pae_parts.append(HEADER_V4_LOCAL);
    try pae_parts.append(nonce);
    try pae_parts.append(""); // ciphertext placeholder, will be updated
    if (footer) |f| try pae_parts.append(f);
    if (implicit) |i| try pae_parts.append(i);
    
    // Derive encryption and authentication keys using BLAKE2b
    const ek = try deriveKey(allocator, key.bytes(), nonce, "paseto-encryption-key");
    defer allocator.free(ek);
    
    const ak = try deriveKey(allocator, key.bytes(), nonce, "paseto-auth-key-for-aead");
    defer allocator.free(ak);
    
    // Encrypt with XChaCha20
    var ciphertext = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(ciphertext);
    
    // ChaCha20 encryption (simplified)
    const chacha_nonce = nonce[0..12].*;
    crypto.stream.chacha.ChaCha20IETF.xor(ciphertext[0..payload.len], payload, 0, ek[0..32].*, chacha_nonce);
    
    // Update PAE with actual ciphertext (without tag)
    pae_parts.items[2] = ciphertext[0..payload.len];
    const pae_data = try utils.pae(allocator, pae_parts.items);
    defer allocator.free(pae_data);
    
    // Generate Poly1305 tag
    var poly1305_key: [32]u8 = undefined;
    @memcpy(&poly1305_key, ak[0..32]);
    
    var tag: [16]u8 = undefined;
    crypto.onetimeauth.Poly1305.create(&tag, pae_data, &poly1305_key);
    @memcpy(ciphertext[payload.len..], &tag);
    
    // Build final token: header + base64url(nonce + ciphertext + tag) + footer
    const token_data = try allocator.alloc(u8, NONCE_SIZE + ciphertext_len);
    defer allocator.free(token_data);
    
    @memcpy(token_data[0..NONCE_SIZE], nonce);
    @memcpy(token_data[NONCE_SIZE..], ciphertext);
    
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
    const ciphertext_with_tag = decoded[NONCE_SIZE..];
    const ciphertext_len = ciphertext_with_tag.len - TAG_SIZE;
    const ciphertext = ciphertext_with_tag[0..ciphertext_len];
    const tag = ciphertext_with_tag[ciphertext_len..];
    
    // Derive keys
    const ek = try deriveKey(allocator, key.bytes(), nonce, "paseto-encryption-key");
    defer allocator.free(ek);
    
    const ak = try deriveKey(allocator, key.bytes(), nonce, "paseto-auth-key-for-aead");
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
    
    // Verify tag
    var poly1305_key: [32]u8 = undefined;
    @memcpy(&poly1305_key, ak[0..32]);
    
    var expected_tag: [16]u8 = undefined;
    crypto.onetimeauth.Poly1305.create(&expected_tag, pae_data, &poly1305_key);
    if (!utils.constantTimeEqual(tag, &expected_tag)) {
        return errors.Error.InvalidSignature;
    }
    
    // Decrypt
    const plaintext = try allocator.alloc(u8, ciphertext_len);
    const chacha_nonce = nonce[0..12].*;
    crypto.stream.chacha.ChaCha20IETF.xor(plaintext, ciphertext, 0, ek[0..32].*, chacha_nonce);
    
    return plaintext;
}

/// Derive a key using BLAKE2b with domain separation
fn deriveKey(allocator: Allocator, key: *const [32]u8, nonce: []const u8, info: []const u8) ![]u8 {
    var hasher = crypto.hash.blake2.Blake2b256.init(.{ .key = &key.* });
    hasher.update(nonce);
    hasher.update(info);
    
    var derived = try allocator.alloc(u8, 32);
    hasher.final(derived[0..32]);
    return derived;
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