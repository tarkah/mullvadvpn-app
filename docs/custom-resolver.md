# Issues with macOS, and how running our own resolver can help overcome them.
When macOS is coming back from sleep or connecting to a new WiFi network, it may try to send various requests over the
internet before it publishes a default route to the routing table. Since our daemon relies on the routing table to
obtain a default route to route traffic to relays and bridges, and since macOS's network reachability seemingly does
too, the daemon won't be able to connect to a relay and thus stay in the blocked state for a prolonged time. However,
all these network interactions are usually preceded by DNS requests for `*.apple.com` domains, and since our firewall
explicitly blocks any traffic on port 53, macOS can't do what it needs to publish a default route to the routing table.
Our firewall rules are what preserves the users privacy and prevent leaks, but they also prevent macOS's morning
routine, starting with the DNS, and then blocking the traffic anyway. If the host was configured to use a resolver
locally, and the daemon would control the resolver, it would be possible to selectively resolve allowed queries and,
before returning the DNS response to the requester, punch a hole in the firewall for the resolved addresses.

# A custom DNS resolver
To allow macOS to function, _some_ DNS queries need to leaked during a blocked state. This can be done via using a
resolver that is controlled by our daemon. When the daemon is in the unsecured state or in the secured state and not in
the error state, the custom resolver should not be in use. When in a blocking state (or just the offline state), the
daemon should configure the system to use a local resolver that's owned by the daemon. On macOS, the resolver should be running
with a specific GUID so that it's traffic can be passed through our firewall based on said GUID.

## Requirements from the daemon
To enable the custom resolver, certain conditions in the rest of the daemon need to be met:
- The firewall must allow traffic coming from our resolver (identified via GID) to the configured upstream resolvers.
- The firewall must have a dynamic list of IPs for which traffic will be allowed to pass. The list will be populated by
  the resolved A and AAAA records, and reset when the TSM moves away from the error state.
- The daemon must configure the system to use the custom resolver.
- The resolver must distinguish between allowed and disallowed queries,

## Local resolver's behavior
### State to keep track of
- The local resolver should have an allow list for the domains that should be queryable, and queries that don't match the
allowlist should be ignored. The allowlist preferably would strictly match domain names rather than just matching
`*.apple.com`. The allowlist is to be static, not changeable at runtime.
- The local resolver's list of upstream resolvers should be configurable by the daemon.
- The daemon should keep track of resolved IP addresses that should be allowed to pass through the firewall.
- The daemon should keep track of what DNS servers should the host try to use, and apply the resolver config to our
custom resolver.
- The daemon should keep track of *if* the user has enabled the custom resolver. If the user enables the custom resovler
    but something is already listening on port 53, then this should be reported back to the front-ends. The user needs
    to know that the custom resolver failed to run.

### Behavior when the resolver is enabled
#### When the resolver setting is disabled.
1. If the host's DNS config is currently using our resolver, this should be reverted.
1. The firewall should be reset to not allow the resolver traffic and the resolved IP traffic through.
1. The custom resolver should be shut down, and stop listening on port 53.

#### When the tunnel state machine starts
1. The custom resolver should be started with approppriate custom resolvers, if the custom resolver is enabled.

#### Behavior when the daemon enters the error state
To enable the custom resolver when entering the error state the daemon should do the following:
1. Configure the host to use our local resolver
1. Exclude the local resolver's traffic from the firewall

#### Resolver's behavior when receiving a DNS query
- When the daemon is in the error state, and the query does match the allowlist:
  1. The query should be forwarded to the upstream resolvers
  1. When receiving the response, it's `A` and `AAAA` records should be allowed through the firewall.
  1. The response should be forwarded to the original requester.
- For all other cases, the query should be dropped.

#### When the daemon leaves the error state:
- The host's configuration should be changed to not use `127.0.0.1:53` as a resolver.
- The list of IP addresses that are allowed to pass through our firewall should be cleared.

### Behavior when the resovler is disabled
#### When the resolver setting is enabled
1. The custom resolver should be started with a GID that let's the firewall identify it's traffic, it should listen on
   port 53, with the host's current resolvers as the upstream resolvers.
1. The firewall should be reset to allow resolver's traffic.
1. If the daemon is in the error state, the host should be configured to use the custom resolver.

## Implementation details
The resolver should be spawned by the tunnel state machine's error state, and it's interactions with the TSM should be
done via passing messages through async channels.

# Issues
- In case there already is a resolver listening on port 53 on the host, the resolver should not become active. In this
    case, the host's config shouldn't be changed to use our resolver.
- Which upstream resolvers should our resolver use? Should it be a public mullvad DNS server? Should it be the resolver
  that the host would normally be configured to use? Using our own resolver improves fingerprintability, using some
  other resolver might allow bad actors to exfiltrate some data (maybe?). Should the customer resolver use the custom
  dns settings if they are set?
- Should the resolved IP addresses that are allowed in the blocked state be cleared after some time, or just after a
    state transition?
- There might be a race condition between the daemon leaving the connected state and entering the offline error state
    during which macOS might try to issue DNS requests that will get lost in the ether.
- Having seen the traffic dumps, it might not be feasible to strictly allow specific domain names without employing
    regular expressions - the subdomains seem to be machine generated.
