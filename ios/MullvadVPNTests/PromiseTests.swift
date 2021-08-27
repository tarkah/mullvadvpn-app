//
//  PromiseTests.swift
//  PromiseTests
//
//  Created by pronebird on 22/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import XCTest

class PromiseTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testObserveResolvedPromise() throws {
        let expect = expectation(description: "Wait for promise")

        Promise(value: 1)
            .observe { completion in
                XCTAssertEqual(completion, .finished(1))
                expect.fulfill()
            }

        wait(for: [expect], timeout: 1)
    }

    func testObservePromise() throws {
        let expect = expectation(description: "Wait for promise")
        Promise<Int> { resolver in
            resolver.resolve(value: 1)
        }
        .observe { completion in
            XCTAssertEqual(completion, .finished(1))
            expect.fulfill()
        }

        wait(for: [expect], timeout: 1)
    }

    func testReceiveOn() throws {
        let expect = expectation(description: "Wait for promise")
        let queue = DispatchQueue(label: "TestQueue")

        Promise(value: 1)
            .receive(on: queue)
            .observe { completion in
                dispatchPrecondition(condition: .onQueue(queue))
                expect.fulfill()
            }

        wait(for: [expect], timeout: 1)
    }

    func testScheduleOn() throws {
        let expect = expectation(description: "Wait for promise")
        let queue = DispatchQueue(label: "TestQueue")

        Promise<Int> { resolver in
            dispatchPrecondition(condition: .onQueue(queue))
            resolver.resolve(value: 1)
        }
        .schedule(on: queue)
        .observe { completion in
            expect.fulfill()
        }

        wait(for: [expect], timeout: 1)
    }

    func testBlockOn() throws {
        let expect1 = expectation(description: "Wait for promise")
        let expect2 = expectation(description: "Wait for queue to be unblocked")
        let queue = DispatchQueue(label: "TestQueue")

        Promise<Int> { resolver in
            DispatchQueue.main.async {
                resolver.resolve(value: 1)
            }
        }
        .block(on: queue)
        .observe { completion in
            dispatchPrecondition(condition: .onQueue(queue))
            expect1.fulfill()
        }

        queue.async {
            expect2.fulfill()
        }

        wait(for: [expect1, expect2], timeout: 1, enforceOrder: true)
    }

    func testCancellation() throws {
        let cancelExpectation = expectation(description: "Expect cancellation handler to trigger")
        let completionExpectation = expectation(description: "Expect promise to complete")

        let promise = Promise<Int> { resolver in
            let work = DispatchWorkItem {
                XCTFail()
                resolver.resolve(value: 1)
            }

            resolver.setCancelHandler {
                work.cancel()
                cancelExpectation.fulfill()
            }

            DispatchQueue.main.async(execute: work)
        }.observe { completion in
            XCTAssertEqual(completion, .cancelled)
            completionExpectation.fulfill()
        }

        promise.cancel()

        wait(for: [cancelExpectation, completionExpectation], timeout: 1)
    }

}
