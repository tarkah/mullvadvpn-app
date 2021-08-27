//
//  TunnelManager.swift
//  MullvadVPN
//
//  Created by pronebird on 25/09/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Foundation
import NetworkExtension
import Logging
import WireGuardKit

/// A private key rotation retry interval on failure (in seconds)
private let kKeyRotationRetryIntervalOnFailure: TimeInterval = 300

/// A private key rotation interval (in days)
private let kKeyRotationInterval = 4

enum MapConnectionStatusError: ChainedError {
    /// A failure to perform the IPC request because the tunnel IPC is already deallocated
    case missingIpc

    /// A failure to send a subsequent IPC request to collect more information, such as tunnel
    /// connection info.
    case ipcRequest(PacketTunnelIpc.Error)

    /// A failure to map the status because the unknown variant of `NEVPNStatus` was given.
    case unknownStatus(NEVPNStatus)

    /// A failure to map the status because the `NEVPNStatus.invalid` variant was given
    /// This happens when attempting to start a tunnel with configuration that does not exist
    /// anymore in system preferences.
    case invalidConfiguration

    var errorDescription: String? {
        switch self {
        case .missingIpc:
            return "Missing IPC"

        case .ipcRequest:
            return "IPC request error"

        case .unknownStatus(let status):
            return "Unknown NEVPNStatus: \(status)"

        case .invalidConfiguration:
            return "Invalid VPN configuration"
        }
    }
}

/// A enum that describes the tunnel state
enum TunnelState: Equatable {
    /// Connecting the tunnel
    case connecting

    /// Connected the tunnel
    case connected(TunnelConnectionInfo)

    /// Disconnecting the tunnel
    case disconnecting

    /// Disconnected the tunnel
    case disconnected

    /// Reconnecting the tunnel. Normally this state appears in response to changing the
    /// relay constraints and asking the running tunnel to reload the configuration.
    case reconnecting(TunnelConnectionInfo)
}

extension TunnelState: CustomStringConvertible, CustomDebugStringConvertible {
    var description: String {
        switch self {
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .disconnecting:
            return "disconnecting"
        case .disconnected:
            return "disconnected"
        case .reconnecting:
            return "reconnecting"
        }
    }

    var debugDescription: String {
        var output = "TunnelState."

        switch self {
        case .connecting:
            output.append("connecting")

        case .connected(let connectionInfo):
            output.append("connected(")
            output.append(String(reflecting: connectionInfo))
            output.append(")")

        case .disconnecting:
            output.append("disconnecting")

        case .disconnected:
            output.append("disconnected")

        case .reconnecting(let connectionInfo):
            output.append("reconnecting(")
            output.append(String(reflecting: connectionInfo))
            output.append(")")
        }

        return output
    }
}

protocol TunnelObserver: AnyObject {
    func tunnelStateDidChange(tunnelState: TunnelState)
    func tunnelSettingsDidChange(tunnelSettings: TunnelSettings?)
}

private class AnyTunnelObserver: WeakObserverBox, TunnelObserver {

    typealias Wrapped = TunnelObserver

    private(set) weak var inner: TunnelObserver?

    init<T: TunnelObserver>(_ inner: T) {
        self.inner = inner
    }

    func tunnelStateDidChange(tunnelState: TunnelState) {
        self.inner?.tunnelStateDidChange(tunnelState: tunnelState)
    }

    func tunnelSettingsDidChange(tunnelSettings: TunnelSettings?) {
        self.inner?.tunnelSettingsDidChange(tunnelSettings: tunnelSettings)
    }

    static func == (lhs: AnyTunnelObserver, rhs: AnyTunnelObserver) -> Bool {
        return lhs.inner === rhs.inner
    }
}

/// A class that provides a convenient interface for VPN tunnels configuration, manipulation and
/// monitoring.
class TunnelManager {

    /// An error emitted by all public methods of TunnelManager
    enum Error: ChainedError {
        /// Account token is not set
        case missingAccount

        /// A failure to start the VPN tunnel via system call
        case startVPNTunnel(Swift.Error)

        /// A failure to load the system VPN configurations created by the app
        case loadAllVPNConfigurations(Swift.Error)

        /// A failure to save the system VPN configuration
        case saveVPNConfiguration(Swift.Error)

        /// A failure to reload the system VPN configuration
        case reloadVPNConfiguration(Swift.Error)

        /// A failure to remove the system VPN configuration
        case removeVPNConfiguration(Swift.Error)

        /// A failure to perform a recovery (by removing the VPN configuration) when a corrupt
        /// VPN configuration is detected.
        case removeInconsistentVPNConfiguration(Swift.Error)

        /// A failure to read tunnel settings
        case readTunnelSettings(TunnelSettingsManager.Error)

        /// A failure to add the tunnel settings
        case addTunnelSettings(TunnelSettingsManager.Error)

        /// A failure to update the tunnel settings
        case updateTunnelSettings(TunnelSettingsManager.Error)

        /// A failure to remove the tunnel settings from Keychain
        case removeTunnelSettings(TunnelSettingsManager.Error)

        /// A failure to migrate tunnel settings
        case migrateTunnelSettings(TunnelSettingsManager.Error)

        /// Unable to obtain the persistent keychain reference for the tunnel settings
        case obtainPersistentKeychainReference(TunnelSettingsManager.Error)

        /// A failure to push the public WireGuard key
        case pushWireguardKey(RestError)

        /// A failure to replace the public WireGuard key
        case replaceWireguardKey(RestError)

        /// A failure to remove the public WireGuard key
        case removeWireguardKey(RestError)

        /// A failure to verify the public WireGuard key
        case verifyWireguardKey(RestError)

        var errorDescription: String? {
            switch self {
            case .missingAccount:
                return "Missing account token"
            case .startVPNTunnel:
                return "Failed to start the VPN tunnel"
            case .loadAllVPNConfigurations:
                return "Failed to load the system VPN configurations"
            case .saveVPNConfiguration:
                return "Failed to save the system VPN configuration"
            case .reloadVPNConfiguration:
                return "Failed to reload the system VPN configuration"
            case .removeVPNConfiguration:
                return "Failed to remove the system VPN configuration"
            case .removeInconsistentVPNConfiguration:
                return "Failed to remove the inconsistent VPN tunnel"
            case .readTunnelSettings:
                return "Failed to read the tunnel settings"
            case .addTunnelSettings:
                return "Failed to add the tunnel settings"
            case .updateTunnelSettings:
                return "Failed to update the tunnel settings"
            case .removeTunnelSettings:
                return "Failed to remove the tunnel settings"
            case .migrateTunnelSettings:
                return "Failed to migrate the tunnel settings"
            case .obtainPersistentKeychainReference:
                return "Failed to obtain the persistent keychain reference"
            case .pushWireguardKey:
                return "Failed to push the WireGuard key to server"
            case .replaceWireguardKey:
                return "Failed to replace the WireGuard key on server"
            case .removeWireguardKey:
                return "Failed to remove the WireGuard key from server"
            case .verifyWireguardKey:
                return "Failed to verify the WireGuard key on server"
            }
        }
    }

    // Switch to stabs on simulator
    #if targetEnvironment(simulator)
    typealias TunnelProviderManagerType = SimulatorTunnelProviderManager
    #else
    typealias TunnelProviderManagerType = NETunnelProviderManager
    #endif

    static let shared = TunnelManager()

    // MARK: - Internal variables

    private let logger = Logger(label: "TunnelManager")
    private let dispatchQueue = DispatchQueue(label: "net.mullvad.MullvadVPN.TunnelManager")

    private let rest = MullvadRest()
    private var tunnelProvider: TunnelProviderManagerType?
    private var tunnelIpc: PacketTunnelIpc?

    private let stateLock = NSLock()
    private let observerList = ObserverList<AnyTunnelObserver>()

    /// A VPN connection status observer
    private var connectionStatusObserver: NSObjectProtocol?

    /// An account token associated with the active tunnel
    private var accountToken: String?

    private var _tunnelState = TunnelState.disconnected
    private var _tunnelSettings: TunnelSettings?

    private init() {}

    // MARK: - Public

    private(set) var tunnelState: TunnelState {
        set {
            stateLock.withCriticalBlock {
                guard _tunnelState != newValue else { return }

                logger.info("Set tunnel state: \(newValue)")

                _tunnelState = newValue

                observerList.forEach { (observer) in
                    observer.tunnelStateDidChange(tunnelState: newValue)
                }
            }
        }
        get {
            stateLock.withCriticalBlock {
                return _tunnelState
            }
        }
    }

    /// The last known public key
    private(set) var tunnelSettings: TunnelSettings? {
        set {
            stateLock.withCriticalBlock {
                guard _tunnelSettings != newValue else { return }

                _tunnelSettings = newValue

                observerList.forEach { (observer) in
                    observer.tunnelSettingsDidChange(tunnelSettings: newValue)
                }
            }
        }
        get {
            stateLock.withCriticalBlock {
                return _tunnelSettings
            }
        }
    }

    /// Initialize the TunnelManager with the tunnel from the system.
    ///
    /// The given account token is used to ensure that the system tunnel was configured for the same
    /// account. The system tunnel is removed in case of inconsistency.
    func loadTunnel(accountToken: String?, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        let operation = ResultOperation<(), TunnelManager.Error> { (finish) in
            TunnelProviderManagerType.loadAllFromPreferences { (tunnels, error) in
                self.dispatchQueue.async {
                    if let error = error {
                        finish(.failure(.loadAllVPNConfigurations(error)))
                    } else {
                        self.initializeManager(accountToken: accountToken, tunnels: tunnels, completionHandler: finish)
                    }
                }
            }
        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    /// Refresh tunnel state.
    /// Use this method to update the tunnel state when app transitions from suspended to active
    /// state.
    func refreshTunnelState(completionHandler: (() -> Void)?) {
        let operation = BlockOperation {
            // Reload the last known public key
            if let accountToken = self.accountToken {
                switch Self.loadTunnelSettings(accountToken: accountToken) {
                case .success(let keychainEntry):
                    self.tunnelSettings = keychainEntry.tunnelSettings
                case .failure(let error):
                    self.logger.error(chainedError: error, message: "Failed to reload tunnel settings when refreshing tunnel state.")
                }
            }

            if let status = self.tunnelProvider?.connection.status {
                self.updateTunnelState(connectionStatus: status)
            }

            completionHandler?()
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func startTunnel(completionHandler: @escaping (Result<(), Error>) -> Void) {
        let operation = ResultOperation<(), Error> { (finish) in
            guard let accountToken = self.accountToken else {
                finish(.failure(.missingAccount))
                return
            }

            self.makeTunnelProvider(accountToken: accountToken) { (result) in
                let result = result.flatMap { (tunnelProvider) -> Result<(), Error> in
                    self.setTunnelProvider(tunnelProvider: tunnelProvider)

                    return Result { try tunnelProvider.connection.startVPNTunnel() }
                        .mapError { Error.startVPNTunnel($0) }
                }
                finish(result)
            }
        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func stopTunnel(completionHandler: @escaping (Result<(), Error>) -> Void) {
        let operation = ResultOperation<(), Error> { (finish) in
            guard let tunnelProvider = self.tunnelProvider else {
                finish(.success(()))
                return
            }

            // Disable on-demand when stopping the tunnel to prevent it from coming back up
            tunnelProvider.isOnDemandEnabled = false

            tunnelProvider.saveToPreferences { (error) in
                if let error = error {
                    finish(.failure(.saveVPNConfiguration(error)))
                } else {
                    tunnelProvider.connection.stopVPNTunnel()
                    finish(.success(()))
                }
            }
        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func reconnectTunnel(completionHandler: (() -> Void)?) {
        let operation = AsyncBlockOperation { (finish) in
            guard let tunnelIpc = self.tunnelIpc else {
                finish()
                return
            }

            tunnelIpc.reloadTunnelSettings { (result) in
                if case .failure(let error) = result {
                    self.logger.error(chainedError: error, message: "Failed to reconnect the tunnel")
                }
                finish()
            }
        }

        operation.addDidFinishBlockObserver { (operation) in
            completionHandler?()
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func setAccount(accountToken: String, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        let operation = ResultOperation<(), TunnelManager.Error> { (finish) in
            let result = Self.makeTunnelSettings(accountToken: accountToken)

            guard case .success(let tunnelSettings) = result else {
                finish(result.map { _ in () })
                return
            }

            let interfaceSettings = tunnelSettings.interface
            let publicKeyWithMetadata = interfaceSettings.privateKey.publicKeyWithMetadata

            guard interfaceSettings.addresses.isEmpty else {
                self.tunnelSettings = tunnelSettings
                self.accountToken = accountToken

                finish(.success(()))
                return
            }

            // Push wireguard key if addresses were not received yet
            self.pushWireguardKeyAndUpdateSettings(accountToken: accountToken, publicKey: publicKeyWithMetadata.publicKey) { (result) in
                if case .success(let newTunnelSettings) = result {
                    self.tunnelSettings = newTunnelSettings
                    self.accountToken = accountToken
                }
                finish(result.map { _ in () })
            }
        }
        operation.addDidFinishBlockObserver { [weak self] (operation, result) in
            if case .success = result {
                self?.resumePeriodicKeyRotation()
            }
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    /// Remove the account token and remove the active tunnel
    func unsetAccount(completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        let operation = ResultOperation<(), TunnelManager.Error> { (finish) in
            guard let accountToken = self.accountToken else {
                finish(.failure(.missingAccount))
                return
            }

            let completeOperation = {
                self.accountToken = nil
                self.tunnelSettings = nil

                finish(.success(()))
            }

            let removeTunnel = {
                // Unregister from receiving the tunnel state changes
                self.unregisterConnectionObserver()
                self.tunnelState = .disconnected
                self.tunnelIpc = nil

                // Remove settings from Keychain
                switch TunnelSettingsManager.remove(searchTerm: .accountToken(accountToken)) {
                case .success:
                    break
                case .failure(let error):
                    // Ignore Keychain errors because that normally means that the Keychain
                    // configuration was already removed and we shouldn't be blocking the
                    // user from logging out
                    self.logger.error(chainedError: error, message: "Unset account error")
                }

                guard let tunnelProvider = self.tunnelProvider else {
                    completeOperation()
                    return
                }

                self.tunnelProvider = nil

                // Remove VPN configuration
                tunnelProvider.removeFromPreferences(completionHandler: { (error) in
                    self.dispatchQueue.async {
                        if let error = error {
                            // Ignore error if the tunnel was already removed by user
                            if let systemError = error as? NEVPNError, systemError.code == .configurationInvalid {
                                completeOperation()
                            } else {
                                finish(.failure(.removeVPNConfiguration(error)))
                            }
                        } else {
                            completeOperation()
                        }
                    }
                })
            }

            switch Self.loadTunnelSettings(accountToken: accountToken) {
            case .success(let keychainEntry):
                let publicKey = keychainEntry.tunnelSettings
                    .interface
                    .privateKey
                    .publicKeyWithMetadata
                    .publicKey

                self.removeWireguardKeyFromServer(accountToken: accountToken, publicKey: publicKey) { (result) in
                    switch result {
                    case .success(let isRemoved):
                        self.logger.warning("Removed the WireGuard key from server: \(isRemoved)")

                    case .failure(let error):
                        self.logger.error(chainedError: error, message: "Unset account error")
                    }

                    removeTunnel()
                }

            case .failure(let error):
                // Ignore Keychain errors because that normally means that the Keychain
                // configuration was already removed and we shouldn't be blocking the
                // user from logging out
                self.logger.error(chainedError: error, message: "Unset account error")

                removeTunnel()
            }

        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func verifyPublicKey(completionHandler: @escaping (Result<Bool, Error>) -> Void) {
        let makePayloadOperation = ResultOperation<PublicKeyPayload<TokenPayload<EmptyPayload>>, Error> {
            () -> Result<PublicKeyPayload<TokenPayload<EmptyPayload>>, Error> in
            guard let accountToken = self.accountToken else {
                return .failure(.missingAccount)
            }

            return Self.loadTunnelSettings(accountToken: accountToken)
                .map { (keychainEntry) -> PublicKeyPayload<TokenPayload<EmptyPayload>> in
                    let publicKey = keychainEntry.tunnelSettings.interface
                        .privateKey
                        .publicKeyWithMetadata.publicKey.rawValue

                    return PublicKeyPayload(
                        pubKey: publicKey,
                        payload: TokenPayload(token: keychainEntry.accountToken, payload: EmptyPayload())
                    )
            }
        }

        let getPubkeyOperation = self.rest.getWireguardKey()
            .operation(payload: nil)
            .injectResult(from: makePayloadOperation)

        getPubkeyOperation.addDidFinishBlockObserver { (operation, result) in
            let result = result.map { (_) -> Bool in
                return true
            }.mapError { (restError) -> Error in
                return .verifyWireguardKey(restError)
            }

            completionHandler(result)
        }

        operationQueue.addOperations([makePayloadOperation, getPubkeyOperation], waitUntilFinished: false)
    }

    func regeneratePrivateKey(completionHandler: @escaping (Result<(), Error>) -> Void) {
        let operation = ResultOperation<(), Error> { (finish) in
            guard let accountToken = self.accountToken else {
                finish(.failure(.missingAccount))
                return
            }

            let result = Self.loadTunnelSettings(accountToken: accountToken)
            guard case .success(let keychainEntry) = result else {
                finish(result.map { _ in () })
                return
            }

            let newPrivateKey = PrivateKeyWithMetadata()
            let oldPublicKeyMetadata = keychainEntry.tunnelSettings.interface
                .privateKey
                .publicKeyWithMetadata

            self.replaceWireguardKeyAndUpdateSettings(accountToken: accountToken, oldPublicKey: oldPublicKeyMetadata, newPrivateKey: newPrivateKey) { (result) in
                guard case .success(let newTunnelSettings) = result else {
                    finish(result.map { _ in () })
                    return
                }

                self.tunnelSettings = newTunnelSettings

                guard let tunnelIpc = self.tunnelIpc else {
                    finish(.success(()))
                    return
                }

                tunnelIpc.reloadTunnelSettings { (ipcResult) in
                    if case .failure(let error) = ipcResult {
                        // Ignore Packet Tunnel IPC errors but log them
                        self.logger.error(chainedError: error, message: "Failed to IPC the tunnel to reload configuration")
                    }

                    finish(.success(()))
                }
            }
        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    func setRelayConstraints(_ constraints: RelayConstraints, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        self.addOperationToModifyTunnelSettingsAndNotifyPacketTunnel(usingBlock: { (tunnelSettings) in
            tunnelSettings.relayConstraints = constraints
        }, completionHandler: completionHandler)
    }

    func setDNSSettings(_ dnsSettings: DNSSettings, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        self.addOperationToModifyTunnelSettingsAndNotifyPacketTunnel(usingBlock: { (tunnelSettings) in
            tunnelSettings.interface.dnsSettings = dnsSettings
        }, completionHandler: completionHandler)
    }

    // MARK: - Key rotation

    /// A timer source used to schedule a delayed key rotation
    private var keyRotationTimer: DispatchSourceTimer?
    private var keyRotationStatus: KeyRotationStatus = .off

    private enum KeyRotationStatus {
        case on
        case off
        case paused
    }

    func startPeriodicKeyRotation() {
        let operation = AsyncBlockOperation { finish in
            switch self.keyRotationStatus {
            case .on, .paused:
                break

            case .off:
                if self.tunnelSettings == nil {
                    self.logger.debug("Start periodic key rotation in paused state")

                    self.keyRotationStatus = .paused
                } else {
                    self.logger.debug("Start periodic key rotation")

                    self.keyRotationStatus = .on
                    self.scheduleKeyRotation()
                }
            }

            finish()
        }

        exclusityController.addOperation(operation, categories: [.keyRotation])
    }

    func stopPeriodicKeyRotation() {
        let operation = AsyncBlockOperation { finish in
            switch self.keyRotationStatus {
            case .off:
                break

            case .on, .paused:
                self.logger.debug("Stop periodic key rotation")

                self.keyRotationStatus = .off
                self.keyRotationTimer?.cancel()
            }

            finish()
        }

        exclusityController.addOperation(operation, categories: [.keyRotation])
    }

    private func resumePeriodicKeyRotation() {
        let operation = AsyncBlockOperation { finish in
            switch self.keyRotationStatus {
            case .off, .on:
                break

            case .paused:
                if self.tunnelSettings != nil {
                    self.logger.debug("Resume periodic key rotation")

                    self.scheduleKeyRotation()
                    self.keyRotationStatus = .on
                }
            }

            finish()
        }

        exclusityController.addOperation(operation, categories: [.keyRotation])
    }

    private func scheduleKeyRotation() {
        guard let tunnelSettings = tunnelSettings else {
            return
        }

        let creationDate = tunnelSettings.interface.privateKey.creationDate

        if let rotationDate = Self.nextRotation(creationDate: creationDate) {
            scheduleKeyRotationAttempt(fireDate: rotationDate)
        } else {
            logger.error("Failed to compute the date for next key rotation")
            scheduleKeyRotationRetry()
        }
    }

    private func scheduleKeyRotationRetry() {
        let fireDate = Date().addingTimeInterval(kKeyRotationRetryIntervalOnFailure)
        let formattedDate = ISO8601DateFormatter().string(from: fireDate)
        logger.debug("Next key rotation retry: \(formattedDate)")

        scheduleKeyRotationAttempt(fireDate: fireDate)
    }

    private func scheduleKeyRotationAttempt(fireDate: Date) {
        startKeyRotationTimer(fireDate: fireDate) { [weak self] in
            self?.rotateKey { [weak self] result in
                self?.handleKeyRotationResult(result)
            }
        }
    }

    private func handleKeyRotationResult(_ result: Result<Bool, TunnelManager.Error>) {
        switch result {
        case .success:
            scheduleKeyRotation()

        case .failure:
            scheduleKeyRotationRetry()
        }
    }

    private func startKeyRotationTimer(fireDate: Date, block: @escaping () -> Void) {
        let deadline: DispatchWallTime = .now() + .seconds(Int(fireDate.timeIntervalSinceNow))

        let timer = DispatchSource.makeTimerSource(queue: dispatchQueue)
        timer.setEventHandler(handler: block)
        timer.schedule(wallDeadline: deadline)
        timer.resume()

        keyRotationTimer?.cancel()
        keyRotationTimer = timer
    }

    func rotateKey(completionHandler: ((Result<Bool, TunnelManager.Error>) -> Void)?) {
        let operation = ResultOperation<Bool, TunnelManager.Error> { finish in
            guard let tunnelSettings = self.tunnelSettings else {
                finish(.failure(.missingAccount))
                return
            }

            guard Self.shouldRotateKey(creationDate: tunnelSettings.interface.privateKey.creationDate) else {
                self.logger.debug("Skip key rotation")
                finish(.success(false))
                return
            }

            self.logger.debug("Rotate key")

            self.regeneratePrivateKey { result in
                switch result {
                case .success:
                    self.logger.debug("Finished key rotation")
                    finish(.success(true))
                case .failure(let error):
                    self.logger.error(chainedError: error, message: "Failed to rotate the key")
                    finish(.failure(error))
                }
            }
        }

        operation.addDidFinishBlockObserver { operation, result in
            completionHandler?(result)
        }

        exclusityController.addOperation(operation, categories: [.keyRotation])
    }

    private class func nextRotation(creationDate: Date) -> Date? {
        return Calendar.current.date(byAdding: .day, value: kKeyRotationInterval, to: creationDate)
    }

    private class func shouldRotateKey(creationDate: Date) -> Bool {
        return nextRotation(creationDate: creationDate)
            .map { $0 <= Date() } ?? false
    }

    // MARK: - Tunnel observeration

    /// Add tunnel observer.
    /// In order to cancel the observation, either call `removeTunnelObserver(_:)` or simply release
    /// the observer.
    func addObserver<T: TunnelObserver>(_ observer: T) {
        observerList.append(AnyTunnelObserver(observer))
    }

    /// Remove tunnel observer.
    func removeObserver<T: TunnelObserver>(_ observer: T) {
        observerList.remove(AnyTunnelObserver(observer))
    }

    // MARK: - Operation management

    enum OperationCategory {
        case tunnelControl
        case stateUpdate
        case keyRotation
    }

    private lazy var operationQueue: OperationQueue = {
        let queue = OperationQueue()
        queue.underlyingQueue = self.dispatchQueue
        return queue
    }()
    private lazy var exclusityController: ExclusivityController<OperationCategory> = {
        return ExclusivityController(operationQueue: self.operationQueue)
    }()

    // MARK: - Private methods

    private func initializeManager(accountToken: String?, tunnels: [TunnelProviderManagerType]?, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        // Migrate the tunnel settings if needed
        let migrationResult = accountToken.flatMap { self.migrateTunnelSettings(accountToken: $0) }
        switch migrationResult {
        case .success, .none:
            break
        case .failure(let migrationError):
            completionHandler(.failure(migrationError))
            return
        }

        switch (tunnels?.first, accountToken) {
        // Case 1: tunnel exists and account token is set.
        // Verify that tunnel can access the configuration via the persistent keychain reference
        // stored in `passwordReference` field of VPN configuration.
        case (.some(let tunnelProvider), .some(let accountToken)):
            let verificationResult = self.verifyTunnel(tunnelProvider: tunnelProvider, expectedAccountToken: accountToken)
            let tunnelSettingsResult = Self.loadTunnelSettings(accountToken: accountToken)

            switch (verificationResult, tunnelSettingsResult) {
            case (.success(true), .success(let keychainEntry)):
                self.accountToken = accountToken
                self.tunnelSettings = keychainEntry.tunnelSettings
                self.setTunnelProvider(tunnelProvider: tunnelProvider)

                completionHandler(.success(()))

            // Remove the tunnel when failed to verify it but successfuly loaded the tunnel
            // settings.
            case (.failure(let verificationError), .success(let keychainEntry)):
                self.logger.error(chainedError: verificationError, message: "Failed to verify the tunnel but successfully loaded the tunnel settings. Removing the tunnel.")

                // Identical code path as the case below.
                fallthrough

            // Remove the tunnel with corrupt configuration.
            // It will be re-created upon the first attempt to connect the tunnel.
            case (.success(false), .success(let keychainEntry)):
                tunnelProvider.removeFromPreferences { (error) in
                    self.dispatchQueue.async {
                        if let error = error {
                            completionHandler(.failure(.removeInconsistentVPNConfiguration(error)))
                        } else {
                            self.accountToken = accountToken
                            self.tunnelSettings = keychainEntry.tunnelSettings

                            completionHandler(.success(()))
                        }
                    }
                }

            // Remove the tunnel when failed to verify the tunnel and load tunnel settings.
            case (.failure(let verificationError), .failure(_)):
                self.logger.error(chainedError: verificationError, message: "Failed to verify the tunnel and load tunnel settings. Removing the tunnel.")

                tunnelProvider.removeFromPreferences { (error) in
                    if let error = error {
                        completionHandler(.failure(.removeInconsistentVPNConfiguration(error)))
                    } else {
                        completionHandler(.failure(verificationError))
                    }
                }

            // Remove the tunnel when the app is not able to read tunnel settings
            case (.success(_), .failure(let settingsReadError)):
                self.logger.error(chainedError: settingsReadError, message: "Failed to load tunnel settings. Removing the tunnel.")

                tunnelProvider.removeFromPreferences { (error) in
                    if let error = error {
                        completionHandler(.failure(.removeInconsistentVPNConfiguration(error)))
                    } else {
                        completionHandler(.failure(settingsReadError))
                    }
                }
            }

        // Case 2: tunnel exists but account token is unset.
        // Remove the orphaned tunnel.
        case (.some(let tunnelProvider), .none):
            tunnelProvider.removeFromPreferences { (error) in
                self.dispatchQueue.async {
                    if let error = error {
                        completionHandler(.failure(.removeInconsistentVPNConfiguration(error)))
                    } else {
                        completionHandler(.success(()))
                    }
                }
            }

        // Case 3: tunnel does not exist but the account token is set.
        // Verify that tunnel settings exists in keychain.
        case (.none, .some(let accountToken)):
            switch Self.loadTunnelSettings(accountToken: accountToken) {
            case .success(let keychainEntry):
                self.accountToken = accountToken
                self.tunnelSettings = keychainEntry.tunnelSettings

                completionHandler(.success(()))

            case .failure(let error):
                completionHandler(.failure(error))
            }

        // Case 4: no tunnels exist and account token is unset.
        case (.none, .none):
            completionHandler(.success(()))
        }
    }

    private func verifyTunnel(tunnelProvider: TunnelProviderManagerType, expectedAccountToken accountToken: String) -> Result<Bool, Error> {
        // Check that the VPN configuration points to the same account token
        guard let username = tunnelProvider.protocolConfiguration?.username, username == accountToken else {
            logger.warning("The token assigned to the VPN configuration does not match the logged in account.")
            return .success(false)
        }

        // Check that the passwordReference, containing the keychain reference for tunnel
        // configuration, is set.
        guard let keychainReference = tunnelProvider.protocolConfiguration?.passwordReference else {
            logger.warning("VPN configuration is missing the passwordReference.")
            return .success(false)
        }

        // Verify that the keychain reference points to the existing entry in Keychain.
        // Bad reference is possible when migrating the user data from one device to the other.
        return TunnelSettingsManager.exists(searchTerm: .persistentReference(keychainReference))
            .mapError { (error) -> Error in
                logger.error(chainedError: error, message: "Failed to verify the persistent keychain reference for tunnel settings.")

                return Error.readTunnelSettings(error)
            }
    }

    /// Set the instance of the active tunnel and add the tunnel status observer
    private func setTunnelProvider(tunnelProvider: TunnelProviderManagerType) {
        guard self.tunnelProvider != tunnelProvider else {
            return
        }

        // Save the new active tunnel provider
        self.tunnelProvider = tunnelProvider

        // Set up tunnel IPC
        let connection = tunnelProvider.connection
        let session = connection as! VPNTunnelProviderSessionProtocol
        let tunnelIpc = PacketTunnelIpc(session: session)
        self.tunnelIpc = tunnelIpc

        // Register for tunnel connection status changes
        unregisterConnectionObserver()
        connectionStatusObserver = NotificationCenter.default
            .addObserver(forName: .NEVPNStatusDidChange, object: connection, queue: nil) {
                [weak self] (notification) in
                guard let self = self else { return }

                let connection = notification.object as? VPNConnectionProtocol

                if let status = connection?.status {
                    self.updateTunnelState(connectionStatus: status)
                }
        }

        // Update the existing state
        updateTunnelState(connectionStatus: connection.status)
    }

    private func unregisterConnectionObserver() {
        if let connectionStatusObserver = connectionStatusObserver {
            NotificationCenter.default.removeObserver(connectionStatusObserver)
            self.connectionStatusObserver = nil
        }
    }

    private func pushWireguardKeyAndUpdateSettings(
        accountToken: String,
        publicKey: PublicKey,
        completionHandler: @escaping (Result<TunnelSettings, Error>) -> Void)
    {
        let payload = TokenPayload(token: accountToken, payload: PushWireguardKeyRequest(pubkey: publicKey.rawValue))
        let operation = rest.pushWireguardKey().operation(payload: payload)

        operation.addDidFinishBlockObserver(queue: dispatchQueue) { (operation, result) in
            let updateResult = result
                .mapError({ (restError) -> Error in
                    return .pushWireguardKey(restError)
                })
                .flatMap { (associatedAddresses) -> Result<TunnelSettings, Error> in
                    return Self.updateTunnelSettings(accountToken: accountToken) { (tunnelSettings) in
                        tunnelSettings.interface.addresses = [
                            associatedAddresses.ipv4Address,
                            associatedAddresses.ipv6Address
                        ]
                    }
                }

            completionHandler(updateResult)
        }

        operationQueue.addOperation(operation)
    }

    private func removeWireguardKeyFromServer(accountToken: String, publicKey: PublicKey, completionHandler: @escaping (Result<Bool, Error>) -> Void) {
        let payload = PublicKeyPayload(pubKey: publicKey.rawValue, payload: TokenPayload(token: accountToken, payload: EmptyPayload()))
        let operation = rest.deleteWireguardKey().operation(payload: payload)

        operation.addDidFinishBlockObserver(queue: dispatchQueue) { (operation, result) in
            let result = result.map({ () -> Bool in
                return true
            }).flatMapError { (restError) -> Result<Bool, Error> in
                if case .server(.pubKeyNotFound) = restError {
                    return .success(false)
                } else {
                    return .failure(.removeWireguardKey(restError))
                }
            }

            completionHandler(result)
        }

        operationQueue.addOperation(operation)
    }

    private func replaceWireguardKeyAndUpdateSettings(
        accountToken: String,
        oldPublicKey: PublicKeyWithMetadata,
        newPrivateKey: PrivateKeyWithMetadata,
        completionHandler: @escaping (Result<TunnelSettings, Error>) -> Void)
    {
        let payload = TokenPayload(
            token: accountToken,
            payload: ReplaceWireguardKeyRequest(
                old: oldPublicKey.publicKey.rawValue,
                new: newPrivateKey.publicKeyWithMetadata.publicKey.rawValue
            )
        )

        let operation = rest.replaceWireguardKey().operation(payload: payload)

        operation.addDidFinishBlockObserver(queue: dispatchQueue) { (operation, result) in
            let updateResult = result
                .mapError({ (restError) -> Error in
                    return .replaceWireguardKey(restError)
                })
                .flatMap { (associatedAddresses) -> Result<TunnelSettings, Error> in
                    return Self.updateTunnelSettings(accountToken: accountToken) { (tunnelSettings) in
                        tunnelSettings.interface.privateKey = newPrivateKey
                        tunnelSettings.interface.addresses = [
                            associatedAddresses.ipv4Address,
                            associatedAddresses.ipv6Address
                        ]
                    }
            }

            completionHandler(updateResult)
        }

        operationQueue.addOperation(operation)
    }

    /// Modify tunnel settings in Keychain and tell Packet Tunnel to reload.
    private func addOperationToModifyTunnelSettingsAndNotifyPacketTunnel(usingBlock block: @escaping (inout TunnelSettings) -> Void, completionHandler: @escaping (Result<(), TunnelManager.Error>) -> Void) {
        let operation = ResultOperation<(), TunnelManager.Error> { (finish) in
            guard let accountToken = self.accountToken else {
                finish(.failure(.missingAccount))
                return
            }

            let result = Self.updateTunnelSettings(accountToken: accountToken, block: block)

            guard case .success(let newTunnelSettings) = result else {
                finish(result.map { _ in () })
                return
            }

            self.tunnelSettings = newTunnelSettings

            guard let tunnelIpc = self.tunnelIpc else {
                finish(.success(()))
                return
            }

            tunnelIpc.reloadTunnelSettings { (ipcResult) in
                // Ignore Packet Tunnel IPC errors but log them
                if case .failure(let error) = ipcResult {
                    self.logger.error(chainedError: error, message: "Failed to reload tunnel settings")
                }

                finish(.success(()))
            }
        }

        operation.addDidFinishBlockObserver { (operation, result) in
            completionHandler(result)
        }

        exclusityController.addOperation(operation, categories: [.tunnelControl])
    }

    /// Initiates the `tunnelState` update
    private func updateTunnelState(connectionStatus: NEVPNStatus) {
        let operation = AsyncBlockOperation { (finish) in
            self.mapTunnelState(connectionStatus: connectionStatus) { (result) in
                switch result {
                case .success(let tunnelState):
                    self.tunnelState = tunnelState

                case .failure(let error):
                    self.logger.error(chainedError: error, message: "Failed to map the tunnel state")
                }

                finish()
            }
        }

        exclusityController.addOperation(operation, categories: [.stateUpdate])
    }

    /// Maps `NEVPNStatus` to `TunnelState`.
    /// Collects the `TunnelConnectionInfo` from the tunnel via IPC if needed before assigning the
    /// `tunnelState`
    private func mapTunnelState(connectionStatus: NEVPNStatus, completionHandler: @escaping (Result<TunnelState, MapConnectionStatusError>) -> Void) {
        switch connectionStatus {
        case .connected:
            guard let tunnelIpc = tunnelIpc else {
                completionHandler(.failure(.missingIpc))
                return
            }

            tunnelIpc.getTunnelInformation { (result) in
                self.dispatchQueue.async {
                    let result = result.map { TunnelState.connected($0) }
                        .mapError { MapConnectionStatusError.ipcRequest($0) }

                    completionHandler(result)
                }
            }

        case .connecting:
            completionHandler(.success(.connecting))

        case .disconnected:
            completionHandler(.success(.disconnected))

        case .disconnecting:
            completionHandler(.success(.disconnecting))

        case .reasserting:
            // Refresh the last known public key on reconnect to cover the possibility of
            // the key being changed due to key rotation.
            if let accountToken = self.accountToken {
                switch Self.loadTunnelSettings(accountToken: accountToken) {
                case .success(let keychainEntry):
                    self.tunnelSettings = keychainEntry.tunnelSettings
                case .failure(let error):
                    self.logger.error(chainedError: error, message: "Failed to refresh tunnel settings upon receiving the .reasserting tunnel state.")
                }
            }

            guard let tunnelIpc = tunnelIpc else {
                completionHandler(.failure(.missingIpc))
                return
            }

            tunnelIpc.getTunnelInformation { (result) in
                self.dispatchQueue.async {
                    let result = result.map { TunnelState.reconnecting($0) }
                        .mapError { MapConnectionStatusError.ipcRequest($0) }

                    completionHandler(result)
                }
            }

        case .invalid:
            completionHandler(.failure(.invalidConfiguration))

        @unknown default:
            completionHandler(.failure(.unknownStatus(connectionStatus)))
        }
    }

    private func makeTunnelProvider(accountToken: String, completionHandler: @escaping (Result<TunnelProviderManagerType, TunnelManager.Error>) -> Void) {
        TunnelProviderManagerType.loadAllFromPreferences { (tunnels, error) in
            self.dispatchQueue.async {
                if let error = error {
                    completionHandler(.failure(.loadAllVPNConfigurations(error)))
                } else {
                    let result = Self.setupTunnelProvider(accountToken: accountToken, tunnels: tunnels)

                    guard case .success(let tunnelProvider) = result else {
                        completionHandler(result)
                        return
                    }

                    tunnelProvider.saveToPreferences { (error) in
                        self.dispatchQueue.async {
                            if let error = error {
                                completionHandler(.failure(.saveVPNConfiguration(error)))
                            } else {
                                // Refresh connection status after saving the tunnel preferences.
                                // Basically it's only necessary to do for new instances of
                                // `NETunnelProviderManager`, but we do that for the existing ones too
                                // for simplicity as it has no side effects.
                                tunnelProvider.loadFromPreferences { (error) in
                                    self.dispatchQueue.async {
                                        if let error = error {
                                            completionHandler(.failure(.reloadVPNConfiguration(error)))
                                        } else {
                                            completionHandler(.success(tunnelProvider))
                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
    }

    // MARK: - Private class methods

    private class func loadTunnelSettings(accountToken: String) -> Result<TunnelSettingsManager.KeychainEntry, Error> {
        return TunnelSettingsManager.load(searchTerm: .accountToken(accountToken))
            .mapError { Error.readTunnelSettings($0) }
    }

    private class func updateTunnelSettings(accountToken: String, block: (inout TunnelSettings) -> Void) -> Result<TunnelSettings, Error> {
        return TunnelSettingsManager.update(searchTerm: .accountToken(accountToken), using: block)
            .mapError { Error.updateTunnelSettings($0) }
    }

    /// Retrieve the existing `TunnelSettings` or create the new ones
    private class func makeTunnelSettings(accountToken: String) -> Result<TunnelSettings, TunnelManager.Error> {
        return TunnelSettingsManager.load(searchTerm: .accountToken(accountToken))
            .map { $0.tunnelSettings }
            .flatMapError { (error) -> Result<TunnelSettings, TunnelManager.Error> in
                // Return default tunnel configuration if the config is not found in Keychain
                if case .lookupEntry(.itemNotFound) = error {
                    let defaultConfiguration = TunnelSettings()

                    return TunnelSettingsManager
                        .add(configuration: defaultConfiguration, account: accountToken)
                        .mapError { .addTunnelSettings($0) }
                        .map { defaultConfiguration }
                } else {
                    return .failure(.readTunnelSettings(error))
                }
        }
    }

    private class func setupTunnelProvider(accountToken: String ,tunnels: [TunnelProviderManagerType]?) -> Result<TunnelProviderManagerType, Error> {
        // Request persistent keychain reference to tunnel settings
        return TunnelSettingsManager.getPersistentKeychainReference(account: accountToken)
            .map { (passwordReference) -> TunnelProviderManagerType in
                // Get the first available tunnel or make a new one
                let tunnelProvider = tunnels?.first ?? TunnelProviderManagerType()

                let protocolConfig = NETunnelProviderProtocol()
                protocolConfig.providerBundleIdentifier = ApplicationConfiguration.packetTunnelExtensionIdentifier
                protocolConfig.serverAddress = ""
                protocolConfig.username = accountToken
                protocolConfig.passwordReference = passwordReference

                tunnelProvider.isEnabled = true
                tunnelProvider.localizedDescription = "WireGuard"
                tunnelProvider.protocolConfiguration = protocolConfig

                // Enable on-demand VPN, always connect the tunnel when on Wi-Fi or cellular
                let alwaysOnRule = NEOnDemandRuleConnect()
                alwaysOnRule.interfaceTypeMatch = .any
                tunnelProvider.onDemandRules = [alwaysOnRule]
                tunnelProvider.isOnDemandEnabled = true

                return tunnelProvider
        }.mapError { (error) -> Error in
            return .obtainPersistentKeychainReference(error)
        }
    }

    private func migrateTunnelSettings(accountToken: String) -> Result<Bool, Error> {
        let result = TunnelSettingsManager
            .migrateKeychainEntry(searchTerm: .accountToken(accountToken))
            .mapError { (error) -> Error in
                return .migrateTunnelSettings(error)
            }

        switch result {
        case .success(let migrated):
            if migrated {
                self.logger.info("Migrated Keychain tunnel configuration.")
            } else {
                self.logger.info("Tunnel settings are up to date. No migration needed.")
            }

        case .failure(let error):
            self.logger.error(chainedError: error)
        }

        return result
    }

}
