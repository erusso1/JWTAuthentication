//
//  File.swift
//  
//
//  Created by Ephraim Russo on 6/6/21.
//

import Vapor
import Fluent
import JWTAuthentication

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
