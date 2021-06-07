
import Vapor
import JWT

struct JWTAccessTokenPayload<U: JWTTokenAuthenticatable>: JWTPayload {
    
    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case issuedAt = "iat"
        case expiration = "exp"
        case identifier = "uuid"
    }
    
    /// The issuer "iss" claim.
    var issuer: IssuerClaim
    
    /// The issued at "iat" claim.
    var issuedAt: IssuedAtClaim
    
    /// The expiration time "exp" claim.
    var expiration: ExpirationClaim
    
    /// The subject "sub" claim, containing the identifier of the associted
    /// `JWTTokenAuthenticatable` type.
    var identifier: U.IDValue
    
    init(
        ttl: TimeInterval,
        issuer: String,
        identifier: U.IDValue
    ) {
        
        let now = Date()
        self.issuer = .init(value: issuer)
        self.issuedAt = .init(value: now)
        self.expiration = .init(value: now.addingTimeInterval(ttl))
        self.identifier = identifier
    }
    
    func verify(using signer: JWTSigner) throws {
        
        try self.expiration.verifyNotExpired()
    }
}

extension JWTAccessTokenPayload: Authenticatable { }
