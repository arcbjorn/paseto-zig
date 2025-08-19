const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const utils = @import("../src/utils.zig");

test "base64url encoding empty string" {
    const allocator = testing.allocator;
    
    const encoded = try utils.base64urlEncode(allocator, "");
    defer allocator.free(encoded);
    
    try testing.expectEqualStrings("", encoded);
}

test "base64url encoding single byte" {
    const allocator = testing.allocator;
    
    const encoded = try utils.base64urlEncode(allocator, "A");
    defer allocator.free(encoded);
    
    try testing.expectEqualStrings("QQ", encoded);
}

test "base64url encoding padding cases" {
    const allocator = testing.allocator;
    
    // Test different padding scenarios
    const test_cases = [_]struct { input: []const u8, expected: []const u8 }{
        .{ .input = "f", .expected = "Zg" },
        .{ .input = "fo", .expected = "Zm8" },
        .{ .input = "foo", .expected = "Zm9v" },
        .{ .input = "foob", .expected = "Zm9vYg" },
        .{ .input = "fooba", .expected = "Zm9vYmE" },
        .{ .input = "foobar", .expected = "Zm9vYmFy" },
    };
    
    for (test_cases) |case| {
        const encoded = try utils.base64urlEncode(allocator, case.input);
        defer allocator.free(encoded);
        
        try testing.expectEqualStrings(case.expected, encoded);
        
        // Test round trip
        const decoded = try utils.base64urlDecode(allocator, encoded);
        defer allocator.free(decoded);
        
        try testing.expectEqualStrings(case.input, decoded);
    }
}

test "base64url with url-safe characters" {
    const allocator = testing.allocator;
    
    // Test data that would contain + and / in regular base64
    const test_data = "\xff\xfe\xfd";
    
    const encoded = try utils.base64urlEncode(allocator, test_data);
    defer allocator.free(encoded);
    
    // Should use - and _ instead of + and /
    try testing.expect(mem.indexOf(u8, encoded, "+") == null);
    try testing.expect(mem.indexOf(u8, encoded, "/") == null);
    try testing.expect(mem.indexOf(u8, encoded, "=") == null); // No padding
    
    const decoded = try utils.base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, test_data, decoded);
}

test "base64url large data" {
    const allocator = testing.allocator;
    
    // Test with larger data
    var large_data: [1000]u8 = undefined;
    for (large_data, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    
    const encoded = try utils.base64urlEncode(allocator, &large_data);
    defer allocator.free(encoded);
    
    const decoded = try utils.base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &large_data, decoded);
}

test "PAE empty list" {
    const allocator = testing.allocator;
    
    const pieces: []const []const u8 = &[_][]const u8{};
    const encoded = try utils.pae(allocator, pieces);
    defer allocator.free(encoded);
    
    try testing.expectEqual(@as(usize, 8), encoded.len);
    
    // Should contain count of 0
    const count = std.mem.readInt(u64, encoded[0..8], .little);
    try testing.expectEqual(@as(u64, 0), count);
}

test "PAE single empty string" {
    const allocator = testing.allocator;
    
    const pieces = [_][]const u8{""};
    const encoded = try utils.pae(allocator, &pieces);
    defer allocator.free(encoded);
    
    try testing.expectEqual(@as(usize, 16), encoded.len); // 8 + 8 + 0
    
    const count = std.mem.readInt(u64, encoded[0..8], .little);
    try testing.expectEqual(@as(u64, 1), count);
    
    const len = std.mem.readInt(u64, encoded[8..16], .little);
    try testing.expectEqual(@as(u64, 0), len);
}

test "PAE multiple strings" {
    const allocator = testing.allocator;
    
    const pieces = [_][]const u8{ "hello", "world", "test" };
    const encoded = try utils.pae(allocator, &pieces);
    defer allocator.free(encoded);
    
    var pos: usize = 0;
    
    // Check count
    const count = std.mem.readInt(u64, encoded[pos..pos + 8], .little);
    try testing.expectEqual(@as(u64, 3), count);
    pos += 8;
    
    // Check each piece
    for (pieces) |piece| {
        const len = std.mem.readInt(u64, encoded[pos..pos + 8], .little);
        try testing.expectEqual(@as(u64, piece.len), len);
        pos += 8;
        
        const data = encoded[pos..pos + piece.len];
        try testing.expectEqualStrings(piece, data);
        pos += piece.len;
    }
}

test "PAE with binary data" {
    const allocator = testing.allocator;
    
    const binary_data = [_]u8{ 0x00, 0xFF, 0x80, 0x7F };
    const pieces = [_][]const u8{&binary_data};
    
    const encoded = try utils.pae(allocator, &pieces);
    defer allocator.free(encoded);
    
    const count = std.mem.readInt(u64, encoded[0..8], .little);
    try testing.expectEqual(@as(u64, 1), count);
    
    const len = std.mem.readInt(u64, encoded[8..16], .little);
    try testing.expectEqual(@as(u64, 4), len);
    
    try testing.expectEqualSlices(u8, &binary_data, encoded[16..20]);
}

test "constant time equal same length" {
    const a = "hello world";
    const b = "hello world";
    const c = "hello worlx";
    
    try testing.expect(utils.constantTimeEqual(a, b));
    try testing.expect(!utils.constantTimeEqual(a, c));
}

test "constant time equal different lengths" {
    const a = "hello";
    const b = "hello world";
    
    try testing.expect(!utils.constantTimeEqual(a, b));
    try testing.expect(!utils.constantTimeEqual(b, a));
}

test "constant time equal empty strings" {
    try testing.expect(utils.constantTimeEqual("", ""));
    try testing.expect(!utils.constantTimeEqual("", "a"));
    try testing.expect(!utils.constantTimeEqual("a", ""));
}

test "constant time equal binary data" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const c = [_]u8{ 0x01, 0x02, 0x03, 0x05 };
    
    try testing.expect(utils.constantTimeEqual(&a, &b));
    try testing.expect(!utils.constantTimeEqual(&a, &c));
}

test "secure zero" {
    var data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    
    utils.secureZero(&data);
    
    for (data) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "timestamp conversion basic" {
    const allocator = testing.allocator;
    
    const timestamp: i64 = 3661; // 1 hour, 1 minute, 1 second
    const rfc3339 = try utils.timestampToRfc3339(allocator, timestamp);
    defer allocator.free(rfc3339);
    
    // Should be in ISO format
    try testing.expect(mem.indexOf(u8, rfc3339, "T") != null);
    try testing.expect(mem.endsWith(u8, rfc3339, "Z"));
    
    // Test parsing back
    const parsed = try utils.rfc3339ToTimestamp(rfc3339);
    try testing.expectEqual(@as(i64, 3661), parsed);
}

test "rfc3339 parsing validation" {
    // Valid format
    try testing.expectEqual(@as(i64, 3723), try utils.rfc3339ToTimestamp("2024-01-01T01:02:03Z"));
    
    // Invalid formats should error
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp(""));
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01"));
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024/01/01T01:02:03Z"));
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01 01:02:03Z"));
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01T01-02-03Z"));
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01T25:02:03Z")); // Invalid hour
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01T01:60:03Z")); // Invalid minute
    try testing.expectError(utils.errors.Error.InvalidTimeFormat, utils.rfc3339ToTimestamp("2024-01-01T01:02:60Z")); // Invalid second
}

test "base64url encode length calculation" {
    try testing.expectEqual(@as(usize, 0), utils.base64urlEncodeLen(0));
    try testing.expectEqual(@as(usize, 4), utils.base64urlEncodeLen(3));
    try testing.expectEqual(@as(usize, 8), utils.base64urlEncodeLen(6));
}

test "PAE deterministic output" {
    const allocator = testing.allocator;
    
    const pieces = [_][]const u8{ "test", "data" };
    
    const encoded1 = try utils.pae(allocator, &pieces);
    defer allocator.free(encoded1);
    
    const encoded2 = try utils.pae(allocator, &pieces);
    defer allocator.free(encoded2);
    
    try testing.expectEqualSlices(u8, encoded1, encoded2);
}

test "PAE order matters" {
    const allocator = testing.allocator;
    
    const pieces1 = [_][]const u8{ "hello", "world" };
    const pieces2 = [_][]const u8{ "world", "hello" };
    
    const encoded1 = try utils.pae(allocator, &pieces1);
    defer allocator.free(encoded1);
    
    const encoded2 = try utils.pae(allocator, &pieces2);
    defer allocator.free(encoded2);
    
    try testing.expect(!mem.eql(u8, encoded1, encoded2));
}

test "base64url invalid input" {
    const allocator = testing.allocator;
    
    // Test with invalid characters (would be valid in regular base64)
    try testing.expectError(error.InvalidCharacter, utils.base64urlDecode(allocator, "SGVsbG8gV29ybGQ+"));
    try testing.expectError(error.InvalidCharacter, utils.base64urlDecode(allocator, "SGVsbG8gV29ybGQ/"));
}

test "constant time equal timing consistency" {
    // This test verifies that comparison time doesn't leak information
    // In practice, timing would need to be measured, but we test the basic logic
    
    const long_a = "a" ** 1000;
    const long_b = "a" ** 999 ++ "b";
    const long_c = "b" ** 1000;
    
    // All should take similar time regardless of where difference occurs
    try testing.expect(!utils.constantTimeEqual(long_a, long_b));
    try testing.expect(!utils.constantTimeEqual(long_a, long_c));
    try testing.expect(!utils.constantTimeEqual(long_b, long_c));
}