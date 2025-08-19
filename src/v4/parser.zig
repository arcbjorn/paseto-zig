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
const builder = @import("builder.zig");

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

/// Validator functions for claim validation
pub const Validator = struct {
    /// Validate audience claim matches expected value
    pub fn forAudience(claims: *const Claims, expected: []const u8) !void {
        if (claims.audience) |aud| {
            if (!mem.eql(u8, aud, expected)) {
                return errors.Error.InvalidAudience;
            }
        } else {
            return errors.Error.MissingAudience;
        }
    }
    
    /// Validate JWT ID claim matches expected value
    pub fn identifiedBy(claims: *const Claims, expected: []const u8) !void {
        if (claims.jwt_id) |jti| {
            if (!mem.eql(u8, jti, expected)) {
                return errors.Error.InvalidJwtId;
            }
        } else {
            return errors.Error.MissingJwtId;
        }
    }
    
    /// Validate issuer claim matches expected value
    pub fn issuedBy(claims: *const Claims, expected: []const u8) !void {
        if (claims.issuer) |iss| {
            if (!mem.eql(u8, iss, expected)) {
                return errors.Error.InvalidIssuer;
            }
        } else {
            return errors.Error.MissingIssuer;
        }
    }
    
    /// Validate subject claim matches expected value
    pub fn subject(claims: *const Claims, expected: []const u8) !void {
        if (claims.subject) |sub| {
            if (!mem.eql(u8, sub, expected)) {
                return errors.Error.InvalidSubject;
            }
        } else {
            return errors.Error.MissingSubject;
        }
    }
    
    /// Validate token is not expired (with optional leeway)
    pub fn notExpired(claims: *const Claims, leeway: i64) !void {
        if (claims.expiration) |exp| {
            const now = std.time.timestamp();
            if (now > exp + leeway) {
                return errors.Error.TokenExpired;
            }
        }
        // If no expiration claim, token doesn't expire
    }
    
    /// Comprehensive time validation (exp, iat, nbf)
    pub fn validAt(claims: *const Claims, leeway: i64) !void {
        const now = std.time.timestamp();
        
        // Check expiration
        if (claims.expiration) |exp| {
            if (now > exp + leeway) {
                return errors.Error.TokenExpired;
            }
        }
        
        // Check not-before
        if (claims.not_before) |nbf| {
            if (now < nbf - leeway) {
                return errors.Error.TokenNotYetValid;
            }
        }
        
        // Check issued-at (token shouldn't be used before it was issued)
        if (claims.issued_at) |iat| {
            if (now < iat - leeway) {
                return errors.Error.TokenUsedBeforeIssued;
            }
        }
    }
};

/// Parser for PASETO tokens with validation
pub const PasetoParser = struct {
    allocator: Allocator,
    validate_time: bool,
    leeway: i64, // Clock skew leeway in seconds
    
    // Validation constraints
    expected_audience: ?[]const u8,
    expected_issuer: ?[]const u8,
    expected_subject: ?[]const u8,
    expected_jwt_id: ?[]const u8,
    
    const Self = @This();
    
    /// Initialize a parser with default settings
    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .validate_time = true,
            .leeway = 60, // 1 minute leeway
            .expected_audience = null,
            .expected_issuer = null,
            .expected_subject = null,
            .expected_jwt_id = null,
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
    
    /// Set expected audience for validation
    pub fn setExpectedAudience(self: *Self, audience: []const u8) *Self {
        self.expected_audience = audience;
        return self;
    }
    
    /// Set expected issuer for validation
    pub fn setExpectedIssuer(self: *Self, issuer: []const u8) *Self {
        self.expected_issuer = issuer;
        return self;
    }
    
    /// Set expected subject for validation
    pub fn setExpectedSubject(self: *Self, subject: []const u8) *Self {
        self.expected_subject = subject;
        return self;
    }
    
    /// Set expected JWT ID for validation
    pub fn setExpectedJwtId(self: *Self, jwt_id: []const u8) *Self {
        self.expected_jwt_id = jwt_id;
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
        
        // Validate claims according to parser configuration
        self.validateClaims(&claims) catch |err| {
            // Clean up the claims before returning the error
            var mutable_claims = claims;
            mutable_claims.deinit(self.allocator);
            return err;
        };
        
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
    
    /// Validate claims according to parser configuration
    fn validateClaims(self: *Self, claims: *const Claims) !void {
        // Time-based validation
        if (self.validate_time) {
            try Validator.validAt(claims, self.leeway);
        }
        
        // Expected claim validation
        if (self.expected_audience) |aud| {
            try Validator.forAudience(claims, aud);
        }
        
        if (self.expected_issuer) |iss| {
            try Validator.issuedBy(claims, iss);
        }
        
        if (self.expected_subject) |sub| {
            try Validator.subject(claims, sub);
        }
        
        if (self.expected_jwt_id) |jti| {
            try Validator.identifiedBy(claims, jti);
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
    _ = parser.setValidateTime(false); // Skip time validation for test
    
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
    _ = parser.setValidateTime(false);
    
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
    _ = parser.setValidateTime(false);
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
    _ = parser.setValidateTime(false);
    
    var claims = try parser.parseLocal(token, &key, footer, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
}

test "Validator forAudience" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    // Test missing audience
    try testing.expectError(errors.Error.MissingAudience,
        Validator.forAudience(&claims, "expected"));
    
    // Test valid audience
    claims.audience = "test-audience";
    try Validator.forAudience(&claims, "test-audience");
    
    // Test invalid audience
    try testing.expectError(errors.Error.InvalidAudience,
        Validator.forAudience(&claims, "wrong-audience"));
}

test "Validator issuedBy" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    // Test missing issuer
    try testing.expectError(errors.Error.MissingIssuer,
        Validator.issuedBy(&claims, "expected"));
    
    // Test valid issuer
    claims.issuer = "test-issuer";
    try Validator.issuedBy(&claims, "test-issuer");
    
    // Test invalid issuer
    try testing.expectError(errors.Error.InvalidIssuer,
        Validator.issuedBy(&claims, "wrong-issuer"));
}

test "Validator subject" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    // Test missing subject
    try testing.expectError(errors.Error.MissingSubject,
        Validator.subject(&claims, "expected"));
    
    // Test valid subject
    claims.subject = "test-subject";
    try Validator.subject(&claims, "test-subject");
    
    // Test invalid subject
    try testing.expectError(errors.Error.InvalidSubject,
        Validator.subject(&claims, "wrong-subject"));
}

test "Validator identifiedBy" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    // Test missing JWT ID
    try testing.expectError(errors.Error.MissingJwtId,
        Validator.identifiedBy(&claims, "expected"));
    
    // Test valid JWT ID
    claims.jwt_id = "test-jwt-id";
    try Validator.identifiedBy(&claims, "test-jwt-id");
    
    // Test invalid JWT ID
    try testing.expectError(errors.Error.InvalidJwtId,
        Validator.identifiedBy(&claims, "wrong-jwt-id"));
}

test "Validator notExpired" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    const now = std.time.timestamp();
    
    // Test no expiration (should pass)
    try Validator.notExpired(&claims, 0);
    
    // Test valid expiration (future)
    claims.expiration = now + 3600; // 1 hour in future
    try Validator.notExpired(&claims, 0);
    
    // Test expired token
    claims.expiration = now - 3600; // 1 hour ago
    try testing.expectError(errors.Error.TokenExpired,
        Validator.notExpired(&claims, 0));
    
    // Test expired token with leeway (should pass)
    try Validator.notExpired(&claims, 7200); // 2 hour leeway
}

test "Validator validAt comprehensive" {
    const allocator = testing.allocator;
    
    var claims = Claims{ .custom = json.ObjectMap.init(allocator) };
    defer claims.custom.deinit();
    
    const now = std.time.timestamp();
    
    // Test all valid times
    claims.expiration = now + 3600;    // expires in 1 hour
    claims.not_before = now - 300;     // valid since 5 minutes ago
    claims.issued_at = now - 300;      // issued 5 minutes ago
    try Validator.validAt(&claims, 60);
    
    // Test expired
    claims.expiration = now - 300;     // expired 5 minutes ago
    try testing.expectError(errors.Error.TokenExpired,
        Validator.validAt(&claims, 0));
    
    // Reset expiration
    claims.expiration = now + 3600;
    
    // Test not yet valid
    claims.not_before = now + 300;     // valid in 5 minutes
    try testing.expectError(errors.Error.TokenNotYetValid,
        Validator.validAt(&claims, 0));
    
    // Reset not_before
    claims.not_before = now - 300;
    
    // Test used before issued
    claims.issued_at = now + 300;      // issued in 5 minutes
    try testing.expectError(errors.Error.TokenUsedBeforeIssued,
        Validator.validAt(&claims, 0));
}

test "PasetoParser with claim validation" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    // Create token with specific claims
    var token_builder = builder.PasetoBuilder.initLocal(allocator);
    defer token_builder.deinit();
    
    _ = try token_builder.setIssuer("test-issuer");
    _ = try token_builder.setSubject("test-subject");
    _ = try token_builder.setAudience("test-audience");
    _ = try token_builder.setJwtId("test-jwt-id");
    _ = try token_builder.withDefaults();
    
    const token = try token_builder.buildLocal(&key);
    defer allocator.free(token);
    
    // Test valid parsing with all validators
    var parser = PasetoParser.init(allocator);
    _ = parser.setExpectedIssuer("test-issuer");
    _ = parser.setExpectedSubject("test-subject");
    _ = parser.setExpectedAudience("test-audience");
    _ = parser.setExpectedJwtId("test-jwt-id");
    _ = parser.setValidateTime(true);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("test-issuer", claims.issuer.?);
    try testing.expectEqualStrings("test-subject", claims.subject.?);
    try testing.expectEqualStrings("test-audience", claims.audience.?);
    try testing.expectEqualStrings("test-jwt-id", claims.jwt_id.?);
}

test "PasetoParser validation failures" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    // Create token with specific claims
    var token_builder = builder.PasetoBuilder.initLocal(allocator);
    defer token_builder.deinit();
    
    _ = try token_builder.setIssuer("test-issuer");
    _ = try token_builder.setSubject("test-subject");
    _ = try token_builder.setAudience("test-audience");
    _ = try token_builder.withDefaults();
    
    const token = try token_builder.buildLocal(&key);
    defer allocator.free(token);
    
    // Test wrong issuer validation
    var parser = PasetoParser.init(allocator);
    _ = parser.setExpectedIssuer("wrong-issuer");
    _ = parser.setValidateTime(false);
    
    try testing.expectError(errors.Error.InvalidIssuer,
        parser.parseLocal(token, &key, null, null));
    
    // Test wrong audience validation
    parser = PasetoParser.init(allocator);
    _ = parser.setExpectedAudience("wrong-audience");
    _ = parser.setValidateTime(false);
    
    try testing.expectError(errors.Error.InvalidAudience,
        parser.parseLocal(token, &key, null, null));
    
    // Test missing JWT ID validation
    parser = PasetoParser.init(allocator);
    _ = parser.setExpectedJwtId("expected-jwt-id");
    _ = parser.setValidateTime(false);
    
    try testing.expectError(errors.Error.MissingJwtId,
        parser.parseLocal(token, &key, null, null));
}

test "Validator fail-closed behavior comprehensive" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    // Create token WITHOUT specific claims
    var token_builder = builder.PasetoBuilder.initLocal(allocator);
    defer token_builder.deinit();
    
    _ = try token_builder.withDefaults(); // Only sets exp and iat
    
    const token = try token_builder.buildLocal(&key);
    defer allocator.free(token);
    
    // Test each missing claim error
    var parser = PasetoParser.init(allocator);
    _ = parser.setValidateTime(false);
    _ = parser.setExpectedIssuer("required-issuer");
    
    try testing.expectError(errors.Error.MissingIssuer,
        parser.parseLocal(token, &key, null, null));
    
    parser = PasetoParser.init(allocator);
    _ = parser.setValidateTime(false);
    _ = parser.setExpectedAudience("required-audience");
    
    try testing.expectError(errors.Error.MissingAudience,
        parser.parseLocal(token, &key, null, null));
    
    parser = PasetoParser.init(allocator);
    _ = parser.setValidateTime(false);
    _ = parser.setExpectedSubject("required-subject");
    
    try testing.expectError(errors.Error.MissingSubject,
        parser.parseLocal(token, &key, null, null));
    
    parser = PasetoParser.init(allocator);
    _ = parser.setValidateTime(false);
    _ = parser.setExpectedJwtId("required-jwt-id");
    
    try testing.expectError(errors.Error.MissingJwtId,
        parser.parseLocal(token, &key, null, null));
}

test "Validator time edge cases" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    const now = std.time.timestamp();
    
    // Create token with borderline time constraints
    var token_builder = builder.PasetoBuilder.initLocal(allocator);
    defer token_builder.deinit();
    
    const exp_time = now + 5; // Expires in 5 seconds
    
    _ = try token_builder.setExpiration(exp_time);
    _ = try token_builder.setIssuer("time-test");
    
    const token = try token_builder.buildLocal(&key);
    defer allocator.free(token);
    
    // Test with different leeway values
    var parser = PasetoParser.init(allocator);
    _ = parser.setExpectedIssuer("time-test");
    _ = parser.setValidateTime(true);
    
    // Should pass with sufficient leeway
    _ = parser.setLeeway(60);
    var claims = try parser.parseLocal(token, &key, null, null);
    claims.deinit(allocator);
    
    // Should pass with moderate leeway
    _ = parser.setLeeway(10);
    claims = try parser.parseLocal(token, &key, null, null);
    claims.deinit(allocator);
}

test "Validator mixed claim scenarios" {
    const allocator = testing.allocator;
    
    var key = keys.LocalKey.generate();
    defer key.deinit();
    
    // Create token with only some claims
    var token_builder = builder.PasetoBuilder.initLocal(allocator);
    defer token_builder.deinit();
    
    _ = try token_builder.setIssuer("partial-issuer");
    _ = try token_builder.setSubject("partial-subject");
    // Intentionally NOT setting audience and jwt_id
    _ = try token_builder.withDefaults();
    
    const token = try token_builder.buildLocal(&key);
    defer allocator.free(token);
    
    // Should succeed with partial validation (only validate existing claims)
    var parser = PasetoParser.init(allocator);
    _ = parser.setExpectedIssuer("partial-issuer");
    _ = parser.setExpectedSubject("partial-subject");
    _ = parser.setValidateTime(true);
    
    var claims = try parser.parseLocal(token, &key, null, null);
    defer claims.deinit(allocator);
    
    try testing.expectEqualStrings("partial-issuer", claims.issuer.?);
    try testing.expectEqualStrings("partial-subject", claims.subject.?);
    try testing.expect(claims.audience == null);
    try testing.expect(claims.jwt_id == null);
}