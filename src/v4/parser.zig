const std = @import("std");
const json = std.json;
const mem = std.mem;
const time = std.time;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const errors = @import("../errors.zig");
const utils = @import("../utils.zig");
const keys = @import("keys.zig");
const local = @import("local.zig");
const public = @import("public.zig");

const LocalKey = keys.LocalKey;
const PublicKey = keys.PublicKey;
const Token = keys.Token;

/// Parsed claims from a PASETO token
pub const Claims = struct {
    issuer: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    expiration: ?i64 = null,
    not_before: ?i64 = null,
    issued_at: ?i64 = null,
    jwt_id: ?[]const u8 = null,
    custom: json.ObjectMap,
    
    const Self = @This();
    
    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.issuer) |iss| allocator.free(iss);
        if (self.subject) |sub| allocator.free(sub);
        if (self.audience) |aud| allocator.free(aud);
        if (self.jwt_id) |jti| allocator.free(jti);
        
        // Free custom claims
        var iterator = self.custom.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| allocator.free(s),
                else => {},
            }
        }
        self.custom.deinit();
    }
};

/// Parser for PASETO tokens with validation
pub const PasetoParser = struct {
    allocator: Allocator,
    validate_time: bool,
    leeway: i64, // Clock skew leeway in seconds
    
    const Self = @This();
    
    /// Initialize a parser with default settings
    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .validate_time = true,
            .leeway = 60, // 1 minute leeway
        };
    }
    
    /// Set whether to validate time claims (exp, nbf)
    pub fn setValidateTime(self: *Self, validate: bool) *Self {
        self.validate_time = validate;
        return self;
    }
    
    /// Set clock skew leeway in seconds
    pub fn setLeeway(self: *Self, leeway: i64) *Self {
        self.leeway = leeway;
        return self;
    }
    
    /// Parse and verify a local token
    pub fn parseLocal(
        self: *Self,
        token: []const u8,
        key: *const LocalKey,
        footer: ?[]const u8,
        implicit: ?[]const u8,
    ) !Claims {
        const payload = try local.decrypt(self.allocator, token, key, footer, implicit);
        defer self.allocator.free(payload);
        
        return self.parseClaims(payload);
    }
    
    /// Parse and verify a public token
    pub fn parsePublic(
        self: *Self,
        token: []const u8,
        public_key: *const PublicKey,
        footer: ?[]const u8,
        implicit: ?[]const u8,
    ) !Claims {
        const payload = try public.verify(self.allocator, token, public_key, footer, implicit);
        defer self.allocator.free(payload);
        
        return self.parseClaims(payload);
    }
    
    /// Parse claims from JSON payload
    fn parseClaims(self: *Self, payload: []const u8) !Claims {
        var parsed = json.parseFromSlice(json.Value, self.allocator, payload, .{}) catch {
            return errors.Error.InvalidJson;
        };
        defer parsed.deinit();
        
        const root = parsed.value;
        if (root != .object) {
            return errors.Error.InvalidPayload;
        }
        
        var claims = Claims{
            .custom = json.ObjectMap.init(self.allocator),
        };
        
        var iterator = root.object.iterator();
        while (iterator.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            
            if (mem.eql(u8, key, "iss")) {
                if (value == .string) {
                    claims.issuer = try self.allocator.dupe(u8, value.string);
                }
            } else if (mem.eql(u8, key, "sub")) {
                if (value == .string) {
                    claims.subject = try self.allocator.dupe(u8, value.string);
                }
            } else if (mem.eql(u8, key, "aud")) {
                if (value == .string) {
                    claims.audience = try self.allocator.dupe(u8, value.string);
                }
            } else if (mem.eql(u8, key, "exp")) {
                if (value == .string) {
                    claims.expiration = utils.rfc3339ToTimestamp(value.string) catch null;
                }
            } else if (mem.eql(u8, key, "nbf")) {
                if (value == .string) {
                    claims.not_before = utils.rfc3339ToTimestamp(value.string) catch null;
                }
            } else if (mem.eql(u8, key, "iat")) {
                if (value == .string) {
                    claims.issued_at = utils.rfc3339ToTimestamp(value.string) catch null;
                }
            } else if (mem.eql(u8, key, "jti")) {
                if (value == .string) {
                    claims.jwt_id = try self.allocator.dupe(u8, value.string);
                }
            } else {
                // Custom claim
                const key_copy = try self.allocator.dupe(u8, key);
                const value_copy = try self.copyJsonValue(value);
                try claims.custom.put(key_copy, value_copy);
            }
        }
        
        // Validate time claims if enabled
        if (self.validate_time) {
            try self.validateTimeClaims(&claims);
        }
        
        return claims;
    }
    
    /// Copy a JSON value, allocating strings
    fn copyJsonValue(self: *Self, value: json.Value) !json.Value {
        return switch (value) {
            .string => |s| json.Value{ .string = try self.allocator.dupe(u8, s) },
            .float => |f| json.Value{ .float = f },
            .integer => |i| json.Value{ .integer = i },
            .bool => |b| json.Value{ .bool = b },
            .null => json.Value.null,
            else => value, // Arrays and objects not fully supported for custom claims
        };
    }
    
    /// Validate time-based claims
    fn validateTimeClaims(self: *Self, claims: *const Claims) !void {
        const now = std.time.timestamp();
        
        // Check expiration
        if (claims.expiration) |exp| {
            if (now > exp + self.leeway) {
                return errors.Error.TokenExpired;
            }
        }
        
        // Check not-before
        if (claims.not_before) |nbf| {
            if (now < nbf - self.leeway) {
                return errors.Error.TokenNotYetValid;
            }
        }
    }
};

test "PasetoParser local token" {
    const allocator = testing.allocator;
    
    // Create a token
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    const payload = 
        \\{"iss":"test-issuer","sub":"test-subject","aud":"test-audience","exp":"2025-01-01T00:00:00Z","custom_claim":"custom_value"}
    ;
    
    const token = try local.encrypt(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    // Parse the token
    var parser = PasetoParser.init(allocator);
    parser.setValidateTime(false); // Skip time validation for test
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expect(claims.issuer != null);
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqualStrings("test-audience", claims.audience.?);
    
    // Check custom claim
    const custom_value = claims.custom.get("custom_claim").?;
    try testing.expectEqualStrings("custom_value", custom_value.string);
}

test "PasetoParser public token" {
    const allocator = testing.allocator;
    
    // Create a token
    var key_pair = keys.KeyPair.generate();
    defer key_pair.deinit();
    
    const payload = 
        \\{"iss":"test-issuer","sub":"test-subject","jti":"unique-id"}
    ;
    
    const token = try public.sign(allocator, payload, &key_pair.secret, null, null);
    defer allocator.free(token);
    
    // Parse the token
    var parser = PasetoParser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parsePublic(token, &key_pair.public, null, null);
    defer claims.deinit(allocator);
    
    try testing.expect(claims.issuer != null);
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqualStrings("unique-id", claims.jwt_id.?);
}

test "PasetoParser time validation" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    // Create expired token
    const now = std.time.timestamp();
    const exp_time = try utils.timestampToRfc3339(allocator, now - 3600); // Expired 1 hour ago
    defer allocator.free(exp_time);
    
    const payload = try std.fmt.allocPrint(allocator, 
        \\{{"iss":"test","exp":"{s}"}}
    , .{exp_time});
    defer allocator.free(payload);
    
    const token = try local.encrypt(allocator, payload, &key, null, null);
    defer allocator.free(token);
    
    // Should fail time validation
    var parser = PasetoParser.init(allocator);
    try testing.expectError(errors.Error.TokenExpired, 
        parser.parseLocal(token, &key, null, null));
    
    // Should succeed with time validation disabled
    parser.setValidateTime(false);
    var claims = try parser.parseLocal(token, &key, null, null);
    claims.deinit(allocator);
}

test "PasetoParser with footer" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    const payload = 
        \\{"iss":"test-issuer"}
    ;
    const footer = "test-footer";
    
    const token = try local.encrypt(allocator, payload, &key, footer, null);
    defer allocator.free(token);
    
    var parser = PasetoParser.init(allocator);
    parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, footer, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
}