//
//  AnyResult.swift
//  AnyResult
//
//  Created by pronebird on 22/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

protocol AnyResult {
    associatedtype Success
    associatedtype Failure: Error

    func asConcreteType() -> Result<Success, Failure>
}

extension Result: AnyResult {
    func asConcreteType() -> Result<Success, Failure> {
        return self
    }
}
