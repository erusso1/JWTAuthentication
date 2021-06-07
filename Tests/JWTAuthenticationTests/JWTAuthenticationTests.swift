import JWT
import XCTVapor
import Fluent
@testable import JWTAuthentication

final class JWTAuthenticationTests: XCTestCase {
   
    private var app: Application!
    
    override func setUpWithError() throws {
        app = .init(.testing)
        try configure(app)
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

    func testMakeToken() {
        
        let planet = Planet(name: "Mars")
        let req = Request(application: app, on: app.eventLoopGroup.next())
        
        XCTAssertThrowsError(
            try planet.jwt.makeToken(on: req)
        ) { error in
            XCTAssertEqual(error.localizedDescription, FluentError.idRequired.localizedDescription)
        }
        
        planet.id = .init(uuidString: "d45009dd-e45a-493e-b432-805235cf7d27")
        
        XCTAssertThrowsError(
            try planet.jwt.makeToken(on: req)
        ) { error in
            XCTAssertEqual(error.localizedDescription, JWTError.missingKIDHeader.localizedDescription)

        }
        
        app.jwt.config.signer = .hs256(key: Environment.get("JWT_SIGNATURE")!)
        
        XCTAssertNoThrow(
            try planet.jwt.makeToken(on: req)
        )
    }
    
    func testTokenClaims() throws {
        
        app.jwt.config.issuer = "test_issuer"
        app.jwt.config.signer = .hs256(key: Environment.get("JWT_SIGNATURE")!)

        let planet = Planet(name: "Mars")
        planet.id = .init(uuidString: "d45009dd-e45a-493e-b432-805235cf7d27")
        let req = Request(application: app, on: app.eventLoopGroup.next())
        let ttl: TimeInterval = 3600
        let token = try planet.jwt.makeToken(on: req, ttl: ttl)
        
        let payload = try req.jwt.verify(token, as: JWTAccessTokenPayload<Planet>.self)
        
        XCTAssertEqual(Int(Date(timeIntervalSinceNow: ttl).timeIntervalSince1970), Int(payload.expiration.value.timeIntervalSince1970))
        XCTAssertEqual(payload.issuer.value, app.jwt.config.issuer)
        XCTAssertEqual(payload.identifier, planet.id)
    }
    
    func testUnauthorizedRequest() throws {
        
        try app.test(.GET, "me") { res in
            XCTAssertEqual(res.status, .unauthorized)
        }
    }
    
    func testAuthorizedRequest() throws {
        
        app.jwt.config.signer = .hs256(key: Environment.get("JWT_SIGNATURE")!)
        
        let planet = Planet(name: "Mars")
        planet.id = .init(uuidString: "d45009dd-e45a-493e-b432-805235cf7d27")
        let req = Request(application: app, on: app.eventLoopGroup.next())
        let token = try planet.jwt.makeToken(on: req)
        
        try app
            .test(.GET, "me") { res in
                XCTAssertEqual(res.status, .unauthorized)
            }
            .test(.GET, "me", headers: ["Authorization": "Bearer \(token)"]) { res in
                XCTAssertEqual(res.status, .ok)
                XCTAssertEqual(res.body.string, "Hello, world!")
            }
    }
    
    static var allTests = [
        ("testConfig", testConfig),
        ("testMakeToken", testMakeToken),
        ("testTokenClaims", testTokenClaims),
        ("testUnauthorizedRequest", testUnauthorizedRequest),
        ("testAuthorizedRequest", testAuthorizedRequest),
    ]
}
