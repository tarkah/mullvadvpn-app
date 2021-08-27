//
//  PacketTunnelRequest.swift
//  PacketTunnelRequest
//
//  Created by pronebird on 27/07/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

/// A enum describing the kinds of requests that `PacketTunnelProvider` handles
enum PacketTunnelRequest: Int, Codable, RawRepresentable, CustomStringConvertible {
    /// Request the tunnel to reload settings
    case reloadTunnelSettings

    /// Request the tunnel connection info
    case tunnelConnectionInfo

    var description: String {
        switch self {
        case .reloadTunnelSettings:
            return "reloadTunnelSettings"
        case .tunnelConnectionInfo:
            return "tunnelConnectionInfo"
        }
    }

    private enum CodingKeys: String, CodingKey {
        case type
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawValue, forKey: CodingKeys.type)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawValue = try container.decode(RawValue.self, forKey: CodingKeys.type)

        if let decoded = PacketTunnelRequest(rawValue: rawValue) {
            self = decoded
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: CodingKeys.type,
                in: container,
                debugDescription: "Unrecognized raw value."
            )
        }
    }
}
