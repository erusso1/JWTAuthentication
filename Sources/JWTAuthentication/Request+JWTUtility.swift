
import JWT
import Vapor

extension Request.JWT {

    public func authorized<U: JWTTokenAuthenticatable>(as authenticatableType: U.Type) throws -> EventLoopFuture<U> {
                        
        let payload = try verify(as: JWTAccessTokenPayload<U>.self)
        
        return authenticatableType.find(payload.identifier, on: _request.db).unwrap(or: Abort(.unauthorized, reason: "Authorized user could not be found"))
    }
}
