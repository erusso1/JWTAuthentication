//
//  File.swift
//  
//
//  Created by Ephraim Russo on 6/6/21.
//

import Vapor
import Fluent

func configure(_ app: Application) throws {

    // register routes
    try routes(app)
}
