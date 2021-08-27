//
//  AnyOptional.swift
//  AnyOptional
//
//  Created by pronebird on 22/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

protocol AnyOptional {
    associatedtype Wrapped

    func asConcreteType() -> Optional<Wrapped>
}

extension Optional: AnyOptional {
    func asConcreteType() -> Optional<Wrapped> {
        return self
    }
}
