//
//  DisplayChainedError.swift
//  MullvadVPN
//
//  Created by pronebird on 04/06/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import StoreKit

protocol DisplayChainedError {
    var errorChainDescription: String? { get }
}

extension RestError: DisplayChainedError {
    var errorChainDescription: String? {
        switch self {
        case .network(let urlError):
            return String(
                format: NSLocalizedString(
                    "NETWORK_ERROR",
                    tableName: "MullvadRest",
                    value: "Network error: %@",
                    comment: "Network error. Use %@ placeholder to place localized failure description."
                ),
                urlError.localizedDescription
            )
        case .server(let serverError):
            if let knownErrorDescription = serverError.errorDescription {
                return knownErrorDescription
            } else {
                return String(
                    format: NSLocalizedString(
                        "SERVER_ERROR",
                        tableName: "MullvadRest",
                        value: "Server error: %@",
                        comment: "Server error. Use %@ placeholder to place localized failure description."
                    ),
                    serverError.error ?? "(empty)"
                )
            }
        case .encodePayload:
            return NSLocalizedString(
                "SERVER_REQUEST_ENCODING_ERROR",
                tableName: "MullvadRest",
                value: "Server request encoding error",
                comment: "Failure to encode the server request."
            )
        case .decodeSuccessResponse:
            return NSLocalizedString(
                "SERVER_SUCCESS_RESPONSE_DECODING_ERROR",
                tableName: "MullvadRest",
                value: "Server success response decoding error",
                comment: "Failure to decode the server success response."
            )
        case .decodeErrorResponse:
            return NSLocalizedString(
                "SERVER_FAILURE_RESPONSE_DECODING_ERROR",
                tableName: "MullvadRest",
                value: "Server error response decoding error",
                comment: "Failure to decode the server failure response."
            )
        }
    }
}

extension TunnelManager.Error: DisplayChainedError {
    var errorChainDescription: String? {
        switch self {
        case .loadAllVPNConfigurations(let systemError):
            return String(
                format: NSLocalizedString(
                    "LOAD_ALL_VPN_CONFIGURATIONS_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to load system VPN configurations: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .reloadVPNConfiguration(let systemError):
            return String(
                format: NSLocalizedString(
                    "RELOAD_VPN_CONFIGURATIONS_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to reload a VPN configuration: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .saveVPNConfiguration(let systemError):
            return String(
                format: NSLocalizedString(
                    "SAVE_VPN_CONFIGURATION_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to save a VPN tunnel configuration: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .obtainPersistentKeychainReference(_):
            return NSLocalizedString(
                "OBTAIN_PERSISTENT_KEYCHAIN_REFERENCE_ERROR",
                tableName: "TunnelManager",
                value: "Failed to obtain the persistent keychain reference for the VPN configuration",
                comment: ""
            )

        case .startVPNTunnel(let systemError):
            return String(
                format: NSLocalizedString(
                    "START_VPN_TUNNEL_ERROR",
                    tableName: "TunnelManager",
                    value: "System error when starting the VPN tunnel: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .removeVPNConfiguration(let systemError):
            return String(
                format: NSLocalizedString(
                    "REMOVE_VPN_CONFIGURATION_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to remove the system VPN configuration: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .removeInconsistentVPNConfiguration(let systemError):
            return String(
                format: NSLocalizedString(
                    "REMOVE_INCONSISTENT_VPN_CONFIGURATION",
                    tableName: "TunnelManager",
                    value: "Failed to remove the outdated system VPN configuration: %@",
                    comment: ""
                ),
                systemError.localizedDescription
            )

        case .readTunnelSettings(_):
            return NSLocalizedString(
                "READ_TUNNEL_SETTINGS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to read tunnel settings",
                comment: ""
            )

        case .addTunnelSettings(_):
            return NSLocalizedString(
                "ADD_TUNNEL_SETTINGS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to add tunnel settings",
                comment: ""
            )

        case .updateTunnelSettings(_):
            return NSLocalizedString(
                "UPDATE_TUNNEL_SETTINGS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to update tunnel settings",
                comment: ""
            )

        case .removeTunnelSettings(_):
            return NSLocalizedString(
                "REMOVE_TUNNEL_SETTINGS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to remove tunnel settings",
                comment: ""
            )

        case .migrateTunnelSettings(_):
            return NSLocalizedString(
                "MIGRATE_TUNNEL_SETTINGS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to migrate tunnel settings",
                comment: ""
            )

        case .pushWireguardKey(let restError):
            let reason = restError.errorChainDescription ?? ""
            var message = String(
                format: NSLocalizedString(
                    "PUSH_WIREGUARD_KEY_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to send the WireGuard key to server: %@",
                    comment: ""
                ),
                reason
            )

            if case .server(.keyLimitReached) = restError {
                // TODO: maybe use `restError.recoverySuggestion` instead?
                message.append("\n\n")
                message.append(NSLocalizedString(
                    "PUSH_WIREGUARD_KEY_RECOVERY_SUGGESTION",
                    tableName: "TunnelManager",
                    value: "Remove unused WireGuard keys and try again",
                    comment: ""
                ))
            }

            return message

        case .replaceWireguardKey(let restError):
            let reason = restError.errorChainDescription ?? ""
            var message = String(
                format: NSLocalizedString(
                    "REPLACE_WIREGUARD_KEY_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to replace the WireGuard key on server: %@",
                    comment: ""
                ),
                reason
            )

            if case .server(.keyLimitReached) = restError {
                // TODO: maybe use `restError.recoverySuggestion` instead?
                message.append("\n\n")
                message.append(NSLocalizedString(
                    "REPLACE_WIREGUARD_KEY_RECOVERY_SUGGESTION",
                    tableName: "TunnelManager",
                    value: "Remove unused WireGuard keys and try again",
                    comment: "")
                )
            }

            return message

        case .removeWireguardKey:
            // This error is never displayed anywhere
            return nil

        case .verifyWireguardKey(let restError):
            let reason = restError.errorChainDescription ?? ""

            return String(
                format: NSLocalizedString(
                    "VERIFY_WIREGUARD_KEY_ERROR",
                    tableName: "TunnelManager",
                    value: "Failed to verify the WireGuard key on server: %@",
                    comment: ""
                ),
                reason
            )

        case .missingAccount:
            return NSLocalizedString(
                "MISSING_ACCOUNT_INTERNAL_ERROR",
                tableName: "TunnelManager",
                value: "Internal error: missing account",
                comment: ""
            )
        case .readRelays:
            return NSLocalizedString(
                "READ_RELAYS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to read relays.",
                comment: ""
            )
        case .cannotSatisfyRelayConstraints:
            return NSLocalizedString(
                "CANNOT_SATISFY_RELAY_CONSTRAINTS_ERROR",
                tableName: "TunnelManager",
                value: "Failed to satisfy relay constraints.",
                comment: ""
            )
        }
    }
}

extension Account.Error: DisplayChainedError {
    var errorChainDescription: String? {
        switch self {
        case .createAccount(let restError), .verifyAccount(let restError):
            return restError.errorChainDescription

        case .tunnelConfiguration(let tunnelError):
            return tunnelError.errorChainDescription
        }
    }
}

extension SKError: LocalizedError {
    public var errorDescription: String? {
        switch self.code {
        case .unknown:
            return NSLocalizedString(
                "UNKNOWN_ERROR",
                tableName: "StoreKitErrors",
                value: "Unknown error",
                comment: ""
            )
        case .clientInvalid:
            return NSLocalizedString(
                "CLIENT_INVALID",
                tableName: "StoreKitErrors",
                value: "Client is not allowed to issue the request",
                comment: ""
            )
        case .paymentCancelled:
            return NSLocalizedString(
                "PAYMENT_CANCELLED",
                tableName: "StoreKitErrors",
                value: "User cancelled the request",
                comment: ""
            )
        case .paymentInvalid:
            return NSLocalizedString(
                "PAYMENT_INVALID",
                tableName: "StoreKitErrors",
                value: "Invalid purchase identifier",
                comment: ""
            )
        case .paymentNotAllowed:
            return NSLocalizedString(
                "PAYMENT_NOT_ALLOWED",
                tableName: "StoreKitErrors",
                value: "This device is not allowed to make the payment",
                comment: ""
            )
        default:
            return self.localizedDescription
        }
    }
}

extension AppStorePaymentManager.Error: DisplayChainedError {
    var errorChainDescription: String? {
        switch self {
        case .noAccountSet:
            return NSLocalizedString(
                "NO_ACCOUNT_SET_ERROR",
                tableName: "AppStorePaymentManager",
                value: "Internal error: account is not set",
                comment: ""
            )

        case .readReceipt(let readReceiptError):
            switch readReceiptError {
            case .refresh(let storeError):
                let skErrorMessage = (storeError as? SKError)?.errorDescription ?? storeError.localizedDescription

                return String(
                    format: NSLocalizedString(
                        "REFRESH_RECEIPT_ERROR",
                        tableName: "AppStorePaymentManager",
                        value: "Cannot refresh the AppStore receipt: %@",
                        comment: ""
                    ),
                    skErrorMessage
                )
            case .io(let ioError):
                return String(
                    format: NSLocalizedString(
                        "READ_RECEIPT_ERROR",
                        tableName: "AppStorePaymentManager",
                        value: "Cannot read the AppStore receipt from disk: %@",
                        comment: ""
                    ),
                    ioError.localizedDescription
                )
            case .doesNotExist:
                return NSLocalizedString(
                    "RECEIPT_NOT_FOUND_ERROR",
                    tableName: "AppStorePaymentManager",
                    value: "AppStore receipt is not found on disk.",
                    comment: ""
                )
            }

        case .sendReceipt(let restError):
            let reason = restError.errorChainDescription ?? ""
            let errorFormat = NSLocalizedString(
                "SEND_RECEIPT_ERROR",
                tableName: "AppStorePaymentManager",
                value: "Failed to send the receipt to server: %@",
                comment: ""
            )
            let recoverySuggestion = NSLocalizedString(
                "SEND_RECEIPT_RECOVERY_SUGGESTION",
                tableName: "AppStorePaymentManager",
                value: "Please retry by using the \"Restore purchases\" button.",
                comment: ""
            )
            var errorString = String(format: errorFormat, reason)
            errorString.append("\n\n")
            errorString.append(recoverySuggestion)
            return errorString

        case .storePayment(let storeError):
            return (storeError as? SKError)?.errorDescription ?? storeError.localizedDescription
        }
    }
}
