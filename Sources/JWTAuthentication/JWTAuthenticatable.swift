
import JWT
import Vapor
import Fluent

public protocol JWTTokenAuthenticatable: Model {
        
    var jwt: JWTHelper<Self> { get }
}

extension JWTTokenAuthenticatable {

    /// A helper used to perform JWT operations such a making a new
    /// token using information provided by the receiver.
    public var jwt: JWTHelper<Self> { .init(self) }
    
    /// Convenience method to create an `Authenticator` directly using
    /// a `JWTTokenAuthenticatable` model.
    ///
    /// For example, a  User model which conforms to `JWTTokenAuthenticatable`
    /// can be used in conjunction with Vapor's `Application` middleware as shown
    /// below:
    ///
    ///     let auth = app.grouped(User.jwtAuthenticator(), User.jwtGuardMiddleware())
    ///
    /// - Returns: A new `Authenticator` instance which attempts to verify the JWT token
    /// found within request headers with respect to the receiver.
    public static func jwtAuthenticator() -> Authenticator {
        JWTAccessTokenPayload<Self>.authenticator()
    }
    
    /// Convenience method to create a `Middleware` instance directly using
    /// a `JWTTokenAuthenticatable` model.
    ///
    /// For example, a  User model which conforms to `JWTTokenAuthenticatable`
    /// can be used in conjunction with Vapor's `Application` middleware as shown
    /// below:
    ///
    ///     let auth = app.grouped(User.jwtAuthenticator(), User.jwtGuardMiddleware())
    ///
    /// - Returns: A new `Middleware` instance which requires that a previous
    /// `Middleware` has verified the JWT token associated with the receiver.
    public static func jwtGuardMiddleware() -> Middleware {
        JWTAccessTokenPayload<Self>.guardMiddleware()
    }
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
