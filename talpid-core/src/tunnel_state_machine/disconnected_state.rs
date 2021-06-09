use super::{
    ConnectingState, ErrorState, EventConsequence, SharedTunnelStateValues, TunnelCommand,
    TunnelCommandReceiver, TunnelState, TunnelStateTransition, TunnelStateWrapper,
};
use crate::firewall::FirewallPolicy;
use futures::StreamExt;
use talpid_types::ErrorExt;

/// No tunnel is running.
pub struct DisconnectedState;

impl DisconnectedState {
    fn set_firewall_policy(
        shared_values: &mut SharedTunnelStateValues,
        should_reset_firewall: bool,
    ) {
        let result = if shared_values.block_when_disconnected {
            let policy = FirewallPolicy::Blocked {
                allow_lan: shared_values.allow_lan,
                allowed_endpoint: shared_values.allowed_endpoint.clone(),
                allowed_ips: shared_values.allowed_ips.clone(),
            };
            Self::set_dns(shared_values);
            shared_values.firewall.apply_policy(policy).map_err(|e| {
                e.display_chain_with_msg(
                    "Failed to apply blocking firewall policy for disconnected state",
                )
            })
        } else if should_reset_firewall {
            shared_values
                .firewall
                .reset_policy()
                .map_err(|e| e.display_chain_with_msg("Failed to reset firewall policy"))
        } else {
            Ok(())
        };
        if let Err(error_chain) = result {
            log::error!("{}", error_chain);
        }
    }

    fn set_dns(shared_values: &mut SharedTunnelStateValues) {
        if let Some(ref dns_servers) = shared_values.dns_servers {
            if let Err(err) = shared_values.dns_monitor.set("lo0", &dns_servers) {
                log::error!("failed to set custom DNS servers: {}", err);
            }
        }
    }

    fn reset_dns(shared_values: &mut SharedTunnelStateValues) {
        if let Err(error) = shared_values.dns_monitor.reset() {
            log::error!("{}", error.display_chain_with_msg("Unable to reset DNS"));
        }
    }
}

impl TunnelState for DisconnectedState {
    type Bootstrap = bool;

    fn enter(
        shared_values: &mut SharedTunnelStateValues,
        should_reset_firewall: Self::Bootstrap,
    ) -> (TunnelStateWrapper, TunnelStateTransition) {
        Self::set_firewall_policy(shared_values, should_reset_firewall);
        #[cfg(target_os = "linux")]
        shared_values.reset_connectivity_check();
        #[cfg(target_os = "android")]
        shared_values.tun_provider.close_tun();

        (
            TunnelStateWrapper::from(DisconnectedState),
            TunnelStateTransition::Disconnected,
        )
    }

    fn handle_event(
        self,
        runtime: &tokio::runtime::Handle,
        commands: &mut TunnelCommandReceiver,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        match runtime.block_on(commands.next()) {
            Some(TunnelCommand::SetAllowedIps(allowed_ips, done_tx)) => {
                if shared_values.set_allowed_ips(allowed_ips) {
                    Self::set_firewall_policy(shared_values, true);
                }
                let _ = done_tx.send(());
                SameState(self.into())
            }
            Some(TunnelCommand::AllowLan(allow_lan)) => {
                if shared_values.allow_lan != allow_lan {
                    // The only platform that can fail is Android, but Android doesn't support the
                    // "block when disconnected" option, so the following call never fails.
                    shared_values
                        .set_allow_lan(allow_lan)
                        .expect("Failed to set allow LAN parameter");

                    Self::set_firewall_policy(shared_values, true);
                }
                SameState(self.into())
            }
            Some(TunnelCommand::AllowEndpoint(endpoint, tx)) => {
                if shared_values.set_allowed_endpoint(endpoint) {
                    Self::set_firewall_policy(shared_values, true);
                }
                if let Err(_) = tx.send(()) {
                    log::error!("The AllowEndpoint receiver was dropped");
                }
                SameState(self.into())
            }
            Some(TunnelCommand::Dns(servers)) => {
                // Same situation as allow LAN above.
                shared_values
                    .set_dns_servers(servers)
                    .expect("Failed to reconnect after changing custom DNS servers");
                Self::set_dns(shared_values);

                SameState(self.into())
            }
            Some(TunnelCommand::BlockWhenDisconnected(block_when_disconnected)) => {
                if shared_values.block_when_disconnected != block_when_disconnected {
                    shared_values.block_when_disconnected = block_when_disconnected;
                    if block_when_disconnected {
                        Self::set_dns(shared_values);
                    } else {
                        Self::reset_dns(shared_values);
                    }
                    Self::set_firewall_policy(shared_values, true);
                }
                SameState(self.into())
            }
            Some(TunnelCommand::IsOffline(is_offline)) => {
                shared_values.is_offline = is_offline;
                SameState(self.into())
            }
            Some(TunnelCommand::Connect) => NewState(ConnectingState::enter(shared_values, 0)),
            Some(TunnelCommand::Block(reason)) => {
                Self::reset_dns(shared_values);
                NewState(ErrorState::enter(shared_values, reason))
            }
            #[cfg(target_os = "android")]
            Some(TunnelCommand::BypassSocket(fd, done_tx)) => {
                shared_values.bypass_socket(fd, done_tx);
                SameState(self.into())
            }
            Some(_) => SameState(self.into()),
            None => {
                Self::reset_dns(shared_values);
                Finished
            }
        }
    }
}
