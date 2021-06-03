use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, Header},
    rr::domain::Name,
};

use std::{
    future::Future,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};

use futures::{
    channel::{mpsc, oneshot},
    future, SinkExt, StreamExt,
};
use tokio1::{
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
};

use trust_dns_client::{
    op::{LowerQuery, Query},
    rr::{LowerName, RecordType},
};
use trust_dns_server::{
    authority::{
        Authority, EmptyLookup, LookupObject, MessageRequest, MessageResponse,
        MessageResponseBuilder, ZoneType,
    },
    client::rr::dnssec::SupportedAlgorithms,
    resolver::config::NameServerConfigGroup,
    server::{Request, RequestHandler, ResponseHandle, ResponseHandler},
    store::forwarder::{ForwardAuthority, ForwardConfig},
    ServerFuture,
};


pub fn start_resolver() {
    std::thread::spawn(run_resolver);
}

pub fn run_resolver() {
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
    match rt.block_on(run_resolver_inner()) {
        Ok(_) => {
            log::error!("Resolver stopped unexpectedly");
        }
        Err(err) => log::error!("Failed to run resolver: {}", err),
    }
}


struct FilteringResolver {
    allowed_zones: Vec<LowerName>,
    forwarder_config: ForwardConfig,
    rx: mpsc::Receiver<ResolverMessage>,
    filtering_state: FilteringState,
    resolver: ForwardAuthority,
    command_sender: mpsc::Sender<IpAddr>,
}

#[derive(Debug, PartialEq)]
pub enum FilteringState {
    On,
    Off,
}

pub enum ResolverMessage {
    Request(LowerQuery, oneshot::Sender<Box<dyn LookupObject>>),
    SetFilteringState(FilteringState, oneshot::Sender<()>),
    SetResolverIps(Vec<IpAddr>, oneshot::Sender<()>),
}


impl FilteringResolver {
    async fn new(command_sender: mpsc::Sender<IpAddr>) -> Result<(Self, mpsc::Sender<ResolverMessage>), String> {
        let (tx, rx) = mpsc::channel(0);
        let forwarder_config = ForwardConfig {
            name_servers: NameServerConfigGroup::cloudflare(),
            options: None,
        };

        let resolver =
            ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &forwarder_config)
                .await
                .map_err(|err| format!(" {}", err))?;


        Ok((
            Self {
                allowed_zones: vec![
                    LowerName::from(Name::from_str("ntp.apple.com").unwrap()),
                    LowerName::from(Name::from_str("apple.com").unwrap()),
                    LowerName::from(Name::from_str("www.apple.com").unwrap()),
                ],
                forwarder_config: ForwardConfig {
                    name_servers: NameServerConfigGroup::cloudflare(),
                    options: None,
                },
                resolver,
                filtering_state: FilteringState::Off,
                rx,
                command_sender,
            },
            tx,
        ))
    }

    async fn run(mut self) {
        use ResolverMessage::*;
        while let Some(message) = self.rx.next().await {
            match message {
                Request(query, tx) => {}
                SetFilteringState(filtering_state, tx) => {}
                SetResolverIps(resolvers, tx) => {}
            }
        }
    }

    fn resolve(&mut self, query: LowerQuery, tx: oneshot::Sender<Box<dyn LookupObject>>) -> impl Future<Output=()> {
        if !self.should_allow_request(query) {
            log::debug!("Blocking query {:?}", query);
            let empty_response = Box::new(EmptyLookup) as Box<dyn LookupObject>;
            tx.send(empty_response);
            Either::B(async {  })
        }

        let lookup = self.resolver.search(&query, false, SupportedAlgorithms::new());
        Either::A(
            async move {
                match lookup.await {
                    Ok(result) => {

                    }
                }

            }
        )
    }

    fn should_allow_request(&self, query: &LowerQuery) -> bool {
        self.filtering_state == FilteringState::Off || self.allow_query(query)
    }

    fn allow_query(&self, query: &LowerQuery) -> bool {
        const ALLOWED_RECORD_TYPES: &[RecordType] =
            &[RecordType::A, RecordType::AAAA, RecordType::CNAME];
        ALLOWED_RECORD_TYPES.contains(&query.query_type())
            && self.allowed_zones.iter().any(|zone| zone == query.name())
    }
}

struct ResolverImpl {
    tx: mpsc::Sender<ResolverMessage>,
}

impl ResolverImpl {
    fn build_response<'a>(
        message: &'a MessageRequest,
        lookup: &'a Box<dyn LookupObject>,
    ) -> MessageResponse<'a, 'a> {
        let mut response_header = Header::new();
        response_header.set_id(message.id());
        response_header.set_op_code(OpCode::Query);
        response_header.set_message_type(MessageType::Response);
        response_header.set_authoritative(false);
        MessageResponseBuilder::new(Some(message.raw_queries())).build(
            response_header,
            lookup.iter(),
            // forwarder responses only contain query answers, no ns,soa or additionals
            Box::new(std::iter::empty()) as Box<dyn Iterator<Item = _> + Send>,
            Box::new(std::iter::empty()) as Box<dyn Iterator<Item = _> + Send>,
            Box::new(std::iter::empty()) as Box<dyn Iterator<Item = _> + Send>,
        )
    }

    fn update(&self, message: &MessageRequest, _response_handler: &mut impl ResponseHandler) {
        log::error!("received update message {:?}", message);
    }

    fn lookup<R: ResponseHandler>(
        &self,
        message: MessageRequest,
        mut response_handler: R,
    ) -> impl Future<Output = ()> + 'static {
        let mut tx = self.tx.clone();

        async move {
            for query in message.queries() {
                let (lookup_tx, lookup_rx) = oneshot::channel();
                let _ = tx
                    .send(ResolverMessage::Request(query.clone(), lookup_tx))
                    .await;
                let lookup_result: Box<dyn LookupObject> = lookup_rx.await.unwrap_or_else(|_| {
                    log::error!("resolver dropped channel");
                    Box::new(EmptyLookup) as Box<dyn LookupObject>
                });
                log::error!("FINISHED WAITING ON A RESPONSE");
                let response = Self::build_response(&message, &lookup_result);

                if let Err(err) = response_handler.send_response(response) {
                    log::error!("Failed to send response: {}", err);
                }
            }
        }
    }
}

impl RequestHandler for ResolverImpl {
    type ResponseFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

    fn handle_request<RT: ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: RT,
    ) -> Self::ResponseFuture {
        if !request.src.ip().is_loopback() {
            return Box::pin(async {});
        }
        match request.message.message_type() {
            MessageType::Query => {
                match request.message.op_code() {
                    OpCode::Query => {
                        return Box::pin(self.lookup(request.message, response_handle));
                    }
                    OpCode::Update => {
                        // TODO: this should be a future
                        self.update(&request.message, &mut response_handle);
                        return Box::pin(async {});
                    }
                    _ => {
                        return Box::pin(async {});
                    }
                };
            }
            _ => Box::pin(async {}),
        }
    }
}


async fn run_resolver_inner() -> Result<(), String> {
    let (resolver, handle) = FilteringResolver::new().await?;
    let resolver_handle = ResolverImpl { tx: handle.clone() };
    let mut server_future = ServerFuture::new(resolver_handle);
    let udp_sock = UdpSocket::bind("0.0.0.0:1053")
        .await
        .map_err(|err| format!("{}", err))?;
    let tcp_sock = TcpListener::bind("0.0.0.0:1053")
        .await
        .map_err(|err| format!("{}", err))?;
    server_future.register_socket(udp_sock);
    server_future.register_listener(tcp_sock, std::time::Duration::from_secs(1));
    server_future
        .block_until_done()
        .await
        .map_err(|err| format!("{}", err))
}
