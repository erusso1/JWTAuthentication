
import JWT
import Vapor
import Fluent

public protocol JWTTokenAuthenticatable: Model {
        
    var jwt: JWTHelper<Self> { get }
}

extension JWTTokenAuthenticatable {

    public var jwt: JWTHelper<Self> { .init(self) }
}

public struct JWTHelper<U: JWTTokenAuthenticatable> {
    
    private let auth: U
    
    init(_ auth: U) {
        self.auth = auth
    }
    
    /// Generates a new JWT token using the receiver's identifier as the
    /// `identifier` claim of the `JWTAccessTokenPayload`.
    /// - Parameter req: The request to perform the JWT signature on.
    /// - Throws: An error if the user's database identifier is not found, or
    /// if the JWT signing failed.
    /// - Returns: A newly generated 
    public func makeToken(on req: Request, ttl: TimeInterval? = nil) throws -> String {
        
        let identifier = try auth.requireID()
        
        let payload = JWTAccessTokenPayload<U>(
            ttl: ttl ?? req.application.jwt.config.expirationTTL,
            issuer: req.application.jwt.config.issuer,
            identifier: identifier)
        
        return try req.jwt.sign(payload)
    }
}
