
import JWT
import Vapor

enum JWTConfig {
    
    static func signerKey() throws -> String {
        guard let signerKey = Environment.get("JWT_SIGNER_KEY") else { throw Abort(.internalServerError, reason: "Authorization not configured properly, check JWTConfig.swift and ensure all values are provided for.") }
        return signerKey
    }
    
    static let header = JWTHeader(alg: "HS256", typ: "JWT")
    
    static func signer() throws -> JWTSigner { JWTSigner.hs256(key: try JWTConfig.signerKey()) }
    
    static let expirationTime: TimeInterval = 100
}
