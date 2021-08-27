//
//  RelaySelectorTests.swift
//  RelaySelectorTests
//
//  Created by pronebird on 07/11/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import XCTest
import Network

class RelaySelectorTests: XCTestCase {

    func testCountryConstraint() {
        let constraints = RelayConstraints(location: .only(.country("es")))

        let result = RelaySelector.evaluate(relays: sampleRelays, constraints: constraints)

        XCTAssertEqual(result?.relay.hostname, "es1-wireguard")
    }

    func testCityConstraint() {
        let constraints = RelayConstraints(location: .only(.city("se", "got")))
        let result = RelaySelector.evaluate(relays: sampleRelays, constraints: constraints)

        XCTAssertEqual(result?.relay.hostname, "se10-wireguard")
    }

    func testHostnameConstraint() {
        let constraints = RelayConstraints(location: .only(.hostname("se", "sto", "se6-wireguard")))

        let result = RelaySelector.evaluate(relays: sampleRelays, constraints: constraints)

        XCTAssertEqual(result?.relay.hostname, "se6-wireguard")
    }

}

private let sampleRelays = ServerRelaysResponse(
    locations: [
        "es-mad": ServerLocation(
            country: "Spain",
            city: "Madrid",
            latitude: 40.408566,
            longitude: -3.69222
        ),
        "se-got": ServerLocation(
            country: "Sweden",
            city: "Gothenburg",
            latitude: 57.70887,
            longitude: 11.97456
        ),
        "se-sto": ServerLocation(
            country: "Sweden",
            city: "Stockholm",
            latitude: 59.3289,
            longitude: 18.0649
        )
    ],
    wireguard: ServerWireguardTunnels(
        ipv4Gateway: .loopback,
        ipv6Gateway: .loopback,
        portRanges: [53...53],
        relays: [
            ServerRelay(
                hostname: "es1-wireguard",
                active: true,
                owned: true,
                location: "es-mad",
                provider: "",
                weight: 500,
                ipv4AddrIn: .loopback,
                ipv6AddrIn: .loopback,
                publicKey: Data(),
                includeInCountry: true
            ),
            ServerRelay(
                hostname: "se10-wireguard",
                active: true,
                owned: true,
                location: "se-got",
                provider: "",
                weight: 1000,
                ipv4AddrIn: .loopback,
                ipv6AddrIn: .loopback,
                publicKey: Data(),
                includeInCountry: true
            ),
            ServerRelay(
                hostname: "se2-wireguard",
                active: true,
                owned: true,
                location: "se-sto",
                provider: "",
                weight: 50,
                ipv4AddrIn: .loopback,
                ipv6AddrIn: .loopback,
                publicKey: Data(),
                includeInCountry: true
            ),
            ServerRelay(
                hostname: "se6-wireguard",
                active: true,
                owned: true,
                location: "se-sto",
                provider: "",
                weight: 100,
                ipv4AddrIn: .loopback,
                ipv6AddrIn: .loopback,
                publicKey: Data(),
                includeInCountry: true
            )
    ])
)
