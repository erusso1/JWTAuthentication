
import JWT
import Vapor

extension Application.JWT {
    
    /// The JWT configuration used to customize global behavior of tokens
    /// generated by the application.
    public var config: JWTConfig { .init(self) }
    
    /// An affordance for encapsulating JWT configuration options such as token
    /// TTL, issuer, and signer.
    public final class JWTConfig {
                
        private let jwt: Application.JWT
        
        init(_ jwt: Application.JWT) {
            self.jwt = jwt
        }
        
        private static var _expirationTTL: TimeInterval = 24 * 60 * 60
        
        private static var _issuer: String = Environment.get("JWT_ISSUER") ?? "JWTAuthentication"
        
        /// The global "exp" claim used by tokens generated by the application.
        ///
        /// The default value is 24 hours.
        public var expirationTTL: TimeInterval {
            get { Self._expirationTTL }
            set { Self._expirationTTL = newValue }
        }
        
        /// The global "iss" claim used by tokens generated by the application.
        ///
        /// The default value is obtained via the `JWT_ISSUER` environment variable. If no value is present, `JWTAuthentication` is used
        /// as default instead.
        public var issuer: String {
            get { Self._issuer }
            set { Self._issuer = newValue }
        }
        
        /// The `JWTSigner` used to sign and verify tokens within the application.
        public var signer: JWTSigner? {
            get { jwt.signers.get() }
            set {
                guard let signer = newValue else { return }
                jwt.signers.use(signer)
            }
        }
    }
}
