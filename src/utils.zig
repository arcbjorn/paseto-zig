const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const base64 = std.base64;
const testing = std.testing;

pub const errors = @import("errors.zig");

/// Base64URL encoder without padding
const base64url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".*;
const base64url_encoder = base64.Base64Encoder.init(base64url_alphabet, null);
const base64url_decoder = base64.Base64Decoder.init(base64url_alphabet, null);

/// Encode bytes to base64url without padding
pub fn base64urlEncode(allocator: Allocator, data: []const u8) ![]u8 {
    const encoded_len = base64url_encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = base64url_encoder.encode(encoded, data);
    return encoded;
}

/// Decode base64url string to bytes
pub fn base64urlDecode(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoded_len = try base64url_decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try base64url_decoder.decode(decoded, encoded);
    return decoded;
}

/// Calculate the length needed for base64url encoding
pub fn base64urlEncodeLen(data_len: usize) usize {
    return base64url_encoder.calcSize(data_len);
}

/// Pre-Authentication Encoding (PAE) as defined in PASETO specification
/// PAE encodes a list of strings into a single string for authenticated data
pub fn pae(allocator: Allocator, pieces: []const []const u8) ![]u8 {
    var total_len: usize = 8; // 8 bytes for count
    
    // Calculate total length needed
    for (pieces) |piece| {
        total_len += 8; // 8 bytes for length
        total_len += piece.len; // actual data
    }
    
    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    
    // Encode count as little-endian u64
    std.mem.writeInt(u64, result[pos..pos + 8][0..8], pieces.len, .little);
    pos += 8;
    
    // Encode each piece
    for (pieces) |piece| {
        // Encode length as little-endian u64
        std.mem.writeInt(u64, result[pos..pos + 8][0..8], piece.len, .little);
        pos += 8;
        
        // Copy the actual data
        @memcpy(result[pos..pos + piece.len], piece);
        pos += piece.len;
    }
    
    return result;
}

/// Constant-time comparison of two byte slices
/// Returns true if they are equal, false otherwise
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    
    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    
    return result == 0;
}

/// Zero out memory securely
pub fn secureZero(data: []u8) void {
    std.crypto.utils.secureZero(u8, data);
}

/// Convert timestamp to RFC3339 string (simplified implementation)
pub fn timestampToRfc3339(allocator: Allocator, timestamp: i64) ![]u8 {
    // Simplified implementation - just return a basic ISO format
    // For a real implementation, you'd need proper date/time calculation
    const seconds_since_epoch: u64 = @intCast(timestamp);
    const seconds_in_day = seconds_since_epoch % 86400;
    const hour = seconds_in_day / 3600;
    const minute = (seconds_in_day % 3600) / 60;
    const second = seconds_in_day % 60;
    
    // Simplified - assume year 2024 for demo purposes
    return std.fmt.allocPrint(allocator, "2024-01-01T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ hour, minute, second });
}

/// Parse RFC3339 timestamp to unix timestamp (simplified)
pub fn rfc3339ToTimestamp(time_str: []const u8) !i64 {
    if (time_str.len < 19) return errors.Error.InvalidTimeFormat;
    if (time_str[4] != '-' or time_str[7] != '-' or time_str[10] != 'T' or 
        time_str[13] != ':' or time_str[16] != ':') {
        return errors.Error.InvalidTimeFormat;
    }
    
    const hour = std.fmt.parseInt(u8, time_str[11..13], 10) catch return errors.Error.InvalidTimeFormat;
    const minute = std.fmt.parseInt(u8, time_str[14..16], 10) catch return errors.Error.InvalidTimeFormat;
    const second = std.fmt.parseInt(u8, time_str[17..19], 10) catch return errors.Error.InvalidTimeFormat;
    
    if (hour > 23 or minute > 59 or second > 59) {
        return errors.Error.InvalidTimeFormat;
    }
    
    // Simplified - just return time of day as seconds (for demo purposes)
    const total: u32 = @as(u32, hour) * 3600 + @as(u32, minute) * 60 + @as(u32, second);
    return @intCast(total);
}

test "base64url encoding and decoding" {
    const allocator = testing.allocator;
    
    const test_data = "hello world";
    const encoded = try base64urlEncode(allocator, test_data);
    defer allocator.free(encoded);
    
    const decoded = try base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualStrings(test_data, decoded);
}

test "PAE encoding" {
    const allocator = testing.allocator;
    
    const pieces = [_][]const u8{ "hello", "world" };
    const encoded = try pae(allocator, &pieces);
    defer allocator.free(encoded);
    
    // Should be: count(2) + len(5) + "hello" + len(5) + "world"
    // = 8 + 8 + 5 + 8 + 5 = 34 bytes
    try testing.expect(encoded.len == 34);
    
    // Check count
    const count = std.mem.readInt(u64, encoded[0..8], .little);
    try testing.expect(count == 2);
    
    // Check first piece
    const len1 = std.mem.readInt(u64, encoded[8..16], .little);
    try testing.expect(len1 == 5);
    try testing.expectEqualStrings("hello", encoded[16..21]);
    
    // Check second piece
    const len2 = std.mem.readInt(u64, encoded[21..29], .little);
    try testing.expect(len2 == 5);
    try testing.expectEqualStrings("world", encoded[29..34]);
}

test "constant time comparison" {
    const a = "hello";
    const b = "hello";
    const c = "world";
    
    try testing.expect(constantTimeEqual(a, b) == true);
    try testing.expect(constantTimeEqual(a, c) == false);
    try testing.expect(constantTimeEqual("", "") == true);
    try testing.expect(constantTimeEqual("a", "") == false);
}

test "timestamp conversion" {
    const allocator = testing.allocator;
    
    const timestamp: i64 = 1609459200; // 2021-01-01 00:00:00 UTC
    const rfc3339 = try timestampToRfc3339(allocator, timestamp);
    defer allocator.free(rfc3339);
    
    try testing.expectEqualStrings("2021-01-01T00:00:00Z", rfc3339);
    
    const parsed_timestamp = try rfc3339ToTimestamp(rfc3339);
    try testing.expect(parsed_timestamp == timestamp);
}