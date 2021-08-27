//
//  PromiseObserver.swift
//  PromiseObserver
//
//  Created by pronebird on 22/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

enum PromiseCompletion<Value> {
    case finished(Value)
    case cancelled

    var unwrappedValue: Value? {
        switch self {
        case .finished(let value):
            return value
        case .cancelled:
            return nil
        }
    }

    func map<NewValue>(_ transform: (Value) throws -> NewValue) rethrows -> PromiseCompletion<NewValue> {
        switch self {
        case .finished(let value):
            return .finished(try transform(value))
        case .cancelled:
            return .cancelled
        }
    }
}

extension PromiseCompletion: Equatable where Value: Equatable {
    static func == (lhs: PromiseCompletion<Value>, rhs: PromiseCompletion<Value>) -> Bool {
        switch (lhs, rhs) {
        case (.finished(let lhsValue), .finished(let rhsValue)):
            return lhsValue == rhsValue
        case (.cancelled, .cancelled):
            return true
        case (.finished, .cancelled), (.cancelled, .finished):
            return false
        }
    }
}

protocol PromiseObserver {
    associatedtype Value

    func receiveCompletion(_ completion: PromiseCompletion<Value>)
}

final class AnyPromiseObserver<Value>: PromiseObserver {
    private let onReceiveCompletion: (PromiseCompletion<Value>) -> Void

    init(_ receiveCompletionHandler: @escaping (PromiseCompletion<Value>) -> Void) {
        onReceiveCompletion = receiveCompletionHandler
    }

    func receiveCompletion(_ completion: PromiseCompletion<Value>) {
        onReceiveCompletion(completion)
    }
}
