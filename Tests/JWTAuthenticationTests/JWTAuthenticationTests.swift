import JWT
import XCTVapor
import Fluent
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

    func testAuthenticatable() {
        
        final class Planet: Model, JWTTokenAuthenticatable {
            // Name of the table or collection.
            static let schema = "planets"

            // Unique identifier for this Planet.
            @ID(key: .id)
            var id: UUID?

            // The Planet's name.
            @Field(key: "name")
            var name: String

            // Creates a new, empty Planet.
            init() { }

            // Creates a new Planet with all properties set.
            init(id: UUID? = nil, name: String) {
                self.id = id
                self.name = name
            }
        }
        
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
    
    static var allTests = [
        ("testConfig", testConfig),
    ]
}
