
import JWT
import Vapor

/// Contains JWT configuration parameters used as default values when generating and verifying JWT tokens.
public struct JWTConfig {

    static let defaultExpirationTime: TimeInterval = 24 * 60 * 60
        
    static var signerKey = ""
    
    static let header = JWTHeader(alg: "HS256", typ: "JWT")
    
    static var signer: JWTSigner { .hs256(key: signerKey) }
    
    static var expirationTime: TimeInterval = defaultExpirationTime
}

extension JWTConfig {
    
    /// Use this method to configure signature and expiration time used when generating and verifying JWT tokens.
    /// - Parameters:
    ///   - signerKey: The JWT signature used for token generation and verification.
    ///   - tokenExpirationTime: Custom token expiration time. If no value is provided, the default value of 24 hours is used.
    /// - Important: Ensure your `signerKey` is stored securely in Environment Variables or other secure storage. Never hardcode the value of `signerKey` or check in to source control.
    public static func use(signerKey: String, tokenExpirationTime: TimeInterval? = nil) {
        
        self.signerKey = signerKey
        self.expirationTime = tokenExpirationTime ?? defaultExpirationTime
    }
}
