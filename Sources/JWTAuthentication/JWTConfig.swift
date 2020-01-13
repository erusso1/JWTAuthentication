
import JWT
import Vapor

public struct JWTConfig {
    
    public static let defaultExpirationTime: TimeInterval = 1 * 60 * 60

    public static func use(signerKey: String, tokenExpirationTime: TimeInterval = defaultExpirationTime) {
        
        self.signerKey = signerKey
        self.expirationTime = tokenExpirationTime
    }
        
    static var signerKey = ""
    
    static let header = JWTHeader(alg: "HS256", typ: "JWT")
    
    static var signer: JWTSigner { .hs256(key: signerKey) }
    
    static var expirationTime: TimeInterval = defaultExpirationTime
}
