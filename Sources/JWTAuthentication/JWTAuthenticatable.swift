
import JWT
import Vapor
import Fluent

public protocol JWTTokenAuthenticatable: Model { }

extension JWTTokenAuthenticatable {
    
    /// Generates a new JWT token string using the given `signer`. If no `signer` is provided, the value set in `JWTConfig` will be used by default.
    /// - Parameter signer: The signer used to generated the JWT token string. Passing `nil` will use the value set in `JWTConfig` by default.
    /// - Returns: A new JWT token string encoded with the receiver's `Identifier`.
    public func generateJWTToken(signer: JWTSigner? = nil) throws -> String {
        
        let payload = try generateJWTPayload()
        let header = JWTConfig.header
        let jwt = JWT<JWTAccessTokenPayload>(header: header, payload: payload)
        let tokenData = try (signer ?? JWTConfig
        .signer).sign(jwt)
        
        guard let token = String(data: tokenData, encoding: .utf8) else { throw JWTError.createJWT }
        
        return token
    }
    
    /// Verifies the given `token` using `signer`. This method throws a `JWTError` if the `token` is expired, malformed, or cannot be verified using the given `signer`. If no `signer` is provided, the value set in `JWTConfig` will be used by default.
    /// - Parameters:
    ///   - token: The JWT token string to be verified.
    ///   - signer: The signer used to generated the JWT token string. Passing `nil` will use the value set in `JWTConfig` by default.
    public static func verifyJWTToken(_ token: String, signer: JWTSigner? = nil) throws {
                
        do {
            let _ = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: signer ?? JWTConfig.signer)
        }
        catch {
            throw JWTError.verificationFailed
        }
    }
    
    /// Returns the `Identifier` of the receiving type found within the ecoded payload of the given `token` string.
    /// - Parameters:
    ///   - token: The JWT token string containg a value of
    ///   `JWTAccessTokenPayload<T>`, where T is the type of the receiver.
    ///   - signer: The signer used to generated the JWT token string. Passing `nil` will use the value set in `JWTConfig` by default.
    /// - Returns: The `Identifier` found within the encoded payload of the token string.
    public static func identifier(inJWTToken token: String, signer: JWTSigner? = nil) throws -> ID {
        
        do {
            let jwt = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: signer ?? JWTConfig.signer)
            return jwt.payload.identifier
        }
        catch {
            throw JWTError.verificationFailed
        }
    }
    
    /// Returns the expiration date of the given JWT `token` string, after which verifications will always fail.
    /// - Parameters:
    ///   - token: The JWT token string containing a value of `JWTAccessTokenPayload<T>`, where T is the type of the receiver.
    ///   - signer: The signer used to generated the JWT token string. Passing `nil` will use the value set in `JWTConfig` by default.
    /// - Returns: The expiration date for the given `token`.
    public static func expiration(ofJWTToken token: String, signer: JWTSigner? = nil) throws -> Date {
        
        let jwt = try JWT<JWTAccessTokenPayload<Self>>(from: token, verifiedUsing: signer ?? JWTConfig.signer)
        return jwt.payload.expirationAt.value
    }
    
    /// Returns a Boolean determining if the given JWT `token` string is expired or not.
    /// - Parameters:
    ///   - token: The JWT token string containing a value of `JWTAccessTokenPayload<T>`, where T is the type of the receiver.
    ///   - signer: The signer used to generated the JWT token string. Passing `nil` will use the value set in `JWTConfig` by default.
    /// - Returns: `true` if the given `token` is expired.
    public static func isJWTTokenExpired(token: String, signer: JWTSigner? = nil) throws -> Bool {
        
        Date() > (try expiration(ofJWTToken: token, signer: signer))
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

