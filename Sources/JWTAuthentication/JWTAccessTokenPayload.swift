
import JWT
import Fluent

struct JWTAccessTokenPayload<U: JWTTokenAuthenticatable>: JWTPayload {
    
    var issuer: IssuerClaim
    
    var issuedAt: IssuedAtClaim
    
    var expirationAt: ExpirationClaim
    
    var identifier: U.ID
    
    init(
        issuer: String = "HelloVapor",
        issuedAt: Date = Date(),
        expirationAt: Date = Date().addingTimeInterval(JWTConfig.expirationTime),
        identifier: U.ID) {
    
        self.issuer = .init(value: issuer)
        self.issuedAt = .init(value: issuedAt)
        self.expirationAt = .init(value: expirationAt)
        self.identifier = identifier
    }
    
    func verify(using signer: JWTSigner) throws {
        
        try self.expirationAt.verifyNotExpired()
    }
}
