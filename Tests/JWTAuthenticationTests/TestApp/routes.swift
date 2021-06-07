//
//  File.swift
//  
//
//  Created by Ephraim Russo on 6/6/21.
//

import Fluent
import Vapor
import JWTAuthentication

func routes(_ app: Application) throws {

    let auth = app.grouped(Planet.jwtAuthenticator(), Planet.jwtGuardMiddleware())
    
    auth.get("me") { req -> String in
        return "Hello, world!"
    }
    
    auth.get("me", "planet") { req -> EventLoopFuture<String> in
        try req.jwt
            .authenticated(as: Planet.self)
            .map { "I'd like to go to \($0.name)" }
    }
}
