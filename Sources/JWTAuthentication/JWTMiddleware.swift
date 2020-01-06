
import JWT
import Vapor

public final class JWTMiddleware<U: JWTTokenAuthenticatable>: Middleware {
    
    public func respond(to request: Request, chainingTo next: Responder) throws -> EventLoopFuture<Response> {
     
        let accessToken = try request.jwtToken()
        
        do {
            try U.verifyJWTToken(accessToken)
        }
        catch let error as JWTError {
            throw Abort(.unauthorized, reason: error.reason)
        }
        
        return try next.respond(to: request)
    }
}

extension JWTTokenAuthenticatable {
    
    public static func jwtMiddleware() -> JWTMiddleware<Self> { JWTMiddleware<Self>() }
}