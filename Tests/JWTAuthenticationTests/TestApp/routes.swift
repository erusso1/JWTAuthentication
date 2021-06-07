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
}
