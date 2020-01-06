
import JWT

extension JWTError {
    
    public static let payloadCreation = JWTError(identifier: "JWT.payloadCreation", reason: "User ID not found")
    
    public static let createJWT = JWTError(identifier: "JWT.createJWT", reason: "Error getting token string")
    
    public static let verificationFailed = JWTError(identifier: "JWT.verificationFailed", reason: "JWT verification failed")
}
