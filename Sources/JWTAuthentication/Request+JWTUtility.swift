
import JWT
import Vapor

extension Request {
    
    public func jwtToken() throws -> String {
        
        guard let token = http.headers.bearerAuthorization?.token else { throw Abort(.unauthorized, reason: "Authorization token not found in headers") }
        
        return token
    }
    
    public func jwtAuthorized<U: JWTTokenAuthenticatable>(_ authenticatableType: U.Type) throws -> Future<U> {
                
        let token = try jwtToken()
        
        let userID = try authenticatableType.identifier(inJWTToken: token)
        
        return authenticatableType.find(userID, on: self).unwrap(or: Abort(.unauthorized, reason: "Authorized user could not be found"))
    }
}
