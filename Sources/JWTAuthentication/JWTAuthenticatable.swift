
import JWT
import Vapor
import Fluent

public protocol JWTTokenAuthenticatable: Model { }

extension JWTTokenAuthenticatable {
    
    public func generateJWTToken() throws -> String {
        
        let payload = try generateJWTPayload()
        let header = JWTConfig.header
        let jwt = JWT<JWTAccessTokenPayload>(header: header, payload: payload)
        let tokenData = try JWTConfig.signer.sign(jwt)
        
        guard let token = String(data: tokenData, encoding: .utf8) else { throw JWTError.createJWT }
        
        return token
    }
    
    public static func verifyJWTToken(_ token: String) throws {
                
        do {
            let _ = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: JWTConfig.signer)
        }
        catch {
            throw JWTError.verificationFailed
        }
    }
    
    public static func identifier(inJWTToken token: String) throws -> ID {
        
        do {
            let jwt = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: JWTConfig.signer)
            return jwt.payload.identifier
        }
        catch {
            throw JWTError.verificationFailed
        }
    }
    
    public static func expiration(ofJWTToken token: String) throws -> Date {
        
        let jwt = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: JWTConfig.signer)
        return jwt.payload.expirationAt.value
    }
}

extension JWTTokenAuthenticatable {
    
    private func generateJWTPayload() throws -> JWTAccessTokenPayload<Self> {
        
        do {
            let identifier = try requireID()
            return JWTAccessTokenPayload<Self>(identifier: identifier)
        }
        catch {
            throw JWTError.payloadCreation
        }
    }
}

