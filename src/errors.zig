const std = @import("std");

pub const Error = error{
    // Token validation errors
    InvalidHeader,
    InvalidVersion,
    InvalidPurpose,
    InvalidToken,
    InvalidSignature,
    InvalidNonce,
    InvalidFooter,
    
    // Cryptographic errors
    CryptographicFailure,
    InvalidKey,
    InvalidKeyLength,
    KeyTypeMismatch,
    
    // JSON/Payload errors
    InvalidJson,
    InvalidPayload,
    PayloadTooLarge,
    
    // Footer validation errors
    FooterTooLarge,
    FooterJsonTooDeep,
    FooterTooManyKeys,
    
    // PASERK errors
    InvalidPaserkFormat,
    InvalidPaserkType,
    InvalidPaserkVersion,
    
    // General errors
    OutOfMemory,
    Base64DecodeError,
    Utf8Error,
    
    // Time-based errors
    TokenExpired,
    TokenNotYetValid,
    TokenUsedBeforeIssued,
    InvalidTimeFormat,
    
    // Claim validation errors
    InvalidAudience,
    MissingAudience,
    InvalidIssuer,
    MissingIssuer,
    InvalidSubject,
    MissingSubject,
    InvalidJwtId,
    MissingJwtId,
};

pub fn errorToString(err: Error) []const u8 {
    return switch (err) {
        Error.InvalidHeader => "Invalid token header",
        Error.InvalidVersion => "Invalid PASETO version",
        Error.InvalidPurpose => "Invalid token purpose",
        Error.InvalidToken => "Invalid token format",
        Error.InvalidSignature => "Invalid token signature",
        Error.InvalidNonce => "Invalid nonce",
        Error.InvalidFooter => "Invalid footer",
        Error.CryptographicFailure => "Cryptographic operation failed",
        Error.InvalidKey => "Invalid cryptographic key",
        Error.InvalidKeyLength => "Invalid key length",
        Error.KeyTypeMismatch => "Key type does not match purpose",
        Error.InvalidJson => "Invalid JSON format",
        Error.InvalidPayload => "Invalid payload format",
        Error.PayloadTooLarge => "Payload exceeds maximum size",
        Error.FooterTooLarge => "Footer exceeds maximum size",
        Error.FooterJsonTooDeep => "Footer JSON nesting too deep",
        Error.FooterTooManyKeys => "Footer has too many JSON keys",
        Error.InvalidPaserkFormat => "Invalid PASERK format",
        Error.InvalidPaserkType => "Invalid PASERK type",
        Error.InvalidPaserkVersion => "Invalid PASERK version",
        Error.OutOfMemory => "Out of memory",
        Error.Base64DecodeError => "Base64 decode error",
        Error.Utf8Error => "UTF-8 encoding error",
        Error.TokenExpired => "Token has expired",
        Error.TokenNotYetValid => "Token is not yet valid",
        Error.TokenUsedBeforeIssued => "Token used before it was issued",
        Error.InvalidTimeFormat => "Invalid time format",
        Error.InvalidAudience => "Invalid audience claim",
        Error.MissingAudience => "Missing required audience claim",
        Error.InvalidIssuer => "Invalid issuer claim",
        Error.MissingIssuer => "Missing required issuer claim",
        Error.InvalidSubject => "Invalid subject claim",
        Error.MissingSubject => "Missing required subject claim",
        Error.InvalidJwtId => "Invalid JWT ID claim",
        Error.MissingJwtId => "Missing required JWT ID claim",
    };
}