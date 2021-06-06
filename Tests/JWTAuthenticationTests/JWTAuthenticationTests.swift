import JWT
import XCTVapor
@testable import JWTAuthentication

final class JWTAuthenticationTests: XCTestCase {
   
    private var app: Application!
    
    override func setUp() {
        app = .init(.testing)
    }
    
    override func tearDown() {
        app.shutdown()
    }
    
    func testConfig() {
        
        XCTAssertEqual(app.jwt.config.issuer, "JWTAuthentication")
        XCTAssertEqual(app.jwt.config.expirationTTL, 24 * 60 * 60)
        XCTAssertNil(app.jwt.config.signer)

        let testIssuer = "test_issuer"
        let testTTL: TimeInterval = 10
        app.jwt.config.signer = .hs256(key: Environment.get("JWT_SIGNATURE")!)
        app.jwt.config.issuer = testIssuer
        app.jwt.config.expirationTTL = testTTL
        
        XCTAssertEqual(app.jwt.signers.get()?.algorithm.name, app.jwt.config.signer?.algorithm.name)
        XCTAssertEqual(app.jwt.config.issuer, testIssuer)
        XCTAssertEqual(app.jwt.config.expirationTTL, testTTL)
    }

    static var allTests = [
        ("testConfig", testConfig),
    ]
}
