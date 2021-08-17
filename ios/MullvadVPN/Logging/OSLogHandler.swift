//
//  OSLogHandler.swift
//  OSLogHandler
//
//  Created by pronebird on 16/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import os

struct OSLogHandler: LogHandler {
    var metadata: Logging.Logger.Metadata = [:]
    var logLevel: Logging.Logger.Level = .debug

    private let label: String
    private let osLog: OSLog

    static var osLogRegistry: [String: [String: OSLog]] = [:]
    static let registryLock = NSLock()

    private static func getOSLog(subsystem: String, category: String) -> OSLog {
        return registryLock.withCriticalBlock {
            var perSubsystem = osLogRegistry[subsystem] ?? [:]
            if let log = perSubsystem[category] {
                return log
            } else {
                let newLog = OSLog(subsystem: subsystem, category: category)
                perSubsystem[category] = newLog
                osLogRegistry[subsystem] = perSubsystem
                return newLog
            }
        }
    }

    init(subsystem: String, category: String) {
        self.label = category
        self.osLog = OSLogHandler.getOSLog(subsystem: subsystem, category: category)
    }

    subscript(metadataKey metadataKey: String) -> Logging.Logger.Metadata.Value? {
        get {
            return metadata[metadataKey]
        }
        set(newValue) {
            metadata[metadataKey] = newValue
        }
    }

    func log(level: Logging.Logger.Level,
             message: Logging.Logger.Message,
             metadata: Logging.Logger.Metadata?,
             source: String,
             file: String,
             function: String,
             line: UInt)
    {
        let mergedMetadata = self.metadata.merging(metadata ?? [:]) { (lhs, rhs) -> Logging.Logger.MetadataValue in
            return rhs
        }
        let prettyMetadata = Self.formatMetadata(mergedMetadata)
        let logMessage = prettyMetadata.isEmpty ? message : "\(prettyMetadata) \(message)"

        os_log("%{public}s", log: osLog, type: level.osLogType, "\(logMessage)")
    }

    private static func formatMetadata(_ metadata: Logging.Logger.Metadata) -> String {
        return metadata.map { "\($0)=\($1)" }.joined(separator: " ")
    }
}
extension Logging.Logger.Level {
    var osLogType: OSLogType {
        switch self {
        case .trace, .debug:
            // Console app does not output .debug logs, so mark all .debug logs as .info level.
            return .info
        case .info, .notice, .warning:
            return .info
        case .error, .critical:
            return .error
        }
    }
}
