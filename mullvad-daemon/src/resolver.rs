use trust_dns_client::rr::LowerName;
use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode},
    rr::domain::Name,
};

use std::{
    future::Future,
    sync::{Arc, RwLock},
};

use futures::future;
use tokio1::{
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
};

use trust_dns_client::{op::LowerQuery, rr::RecordType};
use trust_dns_server::{
    authority::{Catalog, MessageRequest, ZoneType},
    resolver::config::NameServerConfigGroup,
    server::{Request, RequestHandler, ResponseHandler},
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

struct FilteringHandler {
    catalog: Catalog,
    allowed_zones: Vec<LowerName>,
    forward_auth: ForwardAuthority,
}

impl FilteringHandler {
    async fn new() -> Result<Self, String> {
        let mut catalog = Catalog::new();

        catalog.upsert(
            LowerName::new(&Name::root()),
            Box::new(Arc::new(RwLock::new(forwarder_authority().await?))),
        );
        Ok(Self {
            catalog,
            allowed_zones: vec![],
            forward_auth: forwarder_authority().await?,
        })
    }

    fn should_allow_request(&self, request: &Request) -> bool {
        request
            .message
            .queries()
            .iter()
            .all(|query| self.allow_query(query))
            && request.src.ip().is_loopback()
    }

    fn allow_query(&self, query: &LowerQuery) -> bool {
        const ALLOWED_RECORD_TYPES: &[RecordType] =
            &[RecordType::A, RecordType::AAAA, RecordType::CNAME];
        ALLOWED_RECORD_TYPES.contains(&query.query_type())
            && self.allowed_zones.iter().any(|zone| zone == query.name())
    }

    fn lookup(
        &self,
        message: &MessageRequest,
        response_handler: &mut impl ResponseHandler,
    ) -> impl Future<Output = ()> + 'static {
        async { () }
        // unimplemented!()
    }

    fn update(&self, message: &MessageRequest, response_handler: &mut impl ResponseHandler) {
        unimplemented!()
    }
}

impl RequestHandler for FilteringHandler {
    type ResponseFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

    fn handle_request<R: ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: R,
    ) -> Self::ResponseFuture {
        match request.message.message_type() {
            MessageType::Query => {
                if !self.should_allow_request(&request) {
                    return Box::pin(async {});
                }
                match request.message.op_code() {
                    OpCode::Query => {
                        return Box::pin(self.lookup(&request.message, &mut response_handle));
                    }
                    OpCode::Update => {
                        // TODO: this should be a future
                        self.update(&request.message, &mut response_handle);
                        return Box::pin(async {});
                    }
                    _ =>  { return Box::pin(async {});  },
                };
            }
            _ => Box::pin(async {}),
        }
    }
}

async fn run_resolver() -> Result<(), String> {
    let mut server_future = ServerFuture::new(FilteringHandler::new().await?);
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
