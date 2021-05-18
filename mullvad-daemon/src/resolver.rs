use trust_dns_client::rr::LowerName;
use trust_dns_proto::rr::domain::Name;

use std::sync::{Arc, RwLock};

use tokio1::{
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
};

use trust_dns_server::{
    authority::{Catalog, ZoneType},
    resolver::config::NameServerConfigGroup,
    store::forwarder::{ForwardAuthority, ForwardConfig},
    ServerFuture,
};


pub fn start_resolver() {
    std::thread::spawn(|| {
        #[cfg(target_os = "macos")]
        if let Some(gid) = talpid_core::macos::get_exclusion_gid() {
            let ret = unsafe { libc::setgid(gid) };
            if ret != 0 {
                log::error!("Failed to set group ID");
                return;
            }
        } else {
            return;
        }

        let rt = Runtime::new().expect("failed to initialize tokio runtime");
        log::debug!("Running DNS resolver");
        match rt.block_on(run_resolver()) {
            Ok(_) => {
                log::error!("Resolver stopped unexpectedly");
            }
            Err(err) => log::error!("Failed to run resolver: {}", err),
        }
    });
}

async fn forwarder_authority() -> Result<ForwardAuthority, String> {
    let config = ForwardConfig {
        name_servers: NameServerConfigGroup::cloudflare(),
        options: None,
    };

    ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &config).await
}
async fn run_resolver() -> Result<(), String> {
    let mut catalog = Catalog::new();

    catalog.upsert(
        LowerName::new(&Name::root()),
        Box::new(Arc::new(RwLock::new(forwarder_authority().await?))),
    );

    let mut server_future = ServerFuture::new(catalog);
    let udp_sock = UdpSocket::bind("0.0.0.0:53")
        .await
        .map_err(|err| format!("{}", err))?;
    let tcp_sock = TcpListener::bind("0.0.0.0:53")
        .await
        .map_err(|err| format!("{}", err))?;
    server_future.register_socket(udp_sock);
    server_future.register_listener(tcp_sock, std::time::Duration::from_secs(1));
    server_future
        .block_until_done()
        .await
        .map_err(|err| format!("{}", err))
}
