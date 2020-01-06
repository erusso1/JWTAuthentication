
import JWT
import Vapor

extension Request {
    
    public func jwtToken() throws -> String {
        
        guard let token = http.headers[.authorization].first else { throw Abort(.unauthorized, reason: "Authorization token not found in headers") }
        
        return token
    }
    
    public func jwtAuthorizedUser<U: JWTTokenAuthenticatable>() throws -> Future<U> {
                
        let token = try jwtToken()
        
        let userID = try U.identifier(inJWTToken: token)
        
        return U.find(userID, on: self).unwrap(or: Abort(.unauthorized, reason: "Authorized user could not be found"))
    }
}
