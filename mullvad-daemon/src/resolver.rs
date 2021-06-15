use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, Header},
    rr::{domain::Name, record_data::RData},
};

use std::{
    future::Future,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};

use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    SinkExt, StreamExt,
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
    server::{Request, RequestHandler, ResponseHandler},
    store::forwarder::{ForwardAuthority, ForwardConfig},
    ServerFuture,
};

pub async fn start_resolver(
    sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
) -> Option<mpsc::Sender<ResolverMessage>> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(|| run_resolver(sender, tx));
    rx.await.map(Some).unwrap_or(None)
}

pub fn run_resolver(
    sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
    done_tx: oneshot::Sender<mpsc::Sender<ResolverMessage>>,
) {
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
    match rt.block_on(run_resolver_inner(sender, done_tx)) {
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
    command_sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
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
    async fn new(
        command_sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
    ) -> Result<(Self, mpsc::Sender<ResolverMessage>), String> {
        let (tx, rx) = mpsc::channel(0);
        let forwarder_config = ForwardConfig {
            name_servers: NameServerConfigGroup::from_ips_clear(
                &[
                    "192.168.3.1".parse().unwrap(),
                    "192.168.1.1".parse().unwrap(),
                ],
                53,
                false,
            ),
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
                forwarder_config,
                resolver,
                filtering_state: FilteringState::On,
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
                Request(query, tx) => {
                    tokio1::spawn(self.resolve(query, tx));
                }
                SetFilteringState(filtering_state, tx) => {
                    self.filtering_state = filtering_state;
                    let _ = tx.send(());
                }
                SetResolverIps(resolvers, tx) => {
                    let forwarder_config = ForwardConfig {
                        name_servers: NameServerConfigGroup::from_ips_clear(&resolvers, 53, false),
                        options: None,
                    };
                    match ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &forwarder_config).await {
                        Ok(resolver) => {
                            self.forwarder_config = forwarder_config;
                            self.resolver = resolver;
                        }
                    };
                    let _ = tx.send(());
                }
            }
        }
    }

    fn resolve(
        &mut self,
        query: LowerQuery,
        tx: oneshot::Sender<Box<dyn LookupObject>>,
    ) -> impl Future<Output = ()> {
        let empty_response = Box::new(EmptyLookup) as Box<dyn LookupObject>;
        if !self.should_block_request(&query) {
            log::error!("Blocking query {}", query);
            let _ = tx.send(empty_response);
            return Either::Left(async {});
        }

        log::error!("Will try to resolve {}", query);
        let mut unblock_tx = self.command_sender.clone();
        let lookup = self
            .resolver
            .search(&query, false, SupportedAlgorithms::new());
        Either::Right(async move {
            match lookup.await {
                Ok(result) => {
                    let ip_records = result
                        .iter()
                        .filter_map(|record| match record.rdata() {
                            RData::A(ipv4) => Some(IpAddr::from(*ipv4)),
                            RData::AAAA(ipv6) => Some(IpAddr::from(*ipv6)),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if !ip_records.is_empty() {
                        log::error!("Successfully resolved {:?} to {:?}", query, ip_records);
                        if self.filtering_state == FilteringState::On {
                            let (done_tx, done_rx) = oneshot::channel();
                            if unblock_tx.send((ip_records, done_tx)).await.is_ok() {
                                let _ = done_rx.await;
                            } else {
                                log::error!("Failed to send IPs to unblocker");
                            }
                        }
                    }
                    if tx.send(Box::new(result)).is_err() {
                        log::error!("Failed to send response to resolver");
                    }
                }
                Err(err) => {
                    log::trace!("Failed to resolve {}: {}", query, err);
                    let _ = tx.send(empty_response);
                }
            }
        })
    }

    fn should_block_request(&self, query: &LowerQuery) -> bool {
        self.filtering_state != FilteringState::Off || !self.allow_query(query)
    }

    fn allow_query(&self, query: &LowerQuery) -> bool {
        const ALLOWED_RECORD_TYPES: &[RecordType] =
            &[RecordType::A, RecordType::AAAA, RecordType::CNAME];
        let apple_com: LowerName = LowerName::from(Name::from_str("apple.com").unwrap());
        ALLOWED_RECORD_TYPES.contains(&query.query_type()) && query.name().zone_of(&apple_com)
        // TODO: Revert to using a known list of allowed zones
        // && self.allowed_zones.iter().any(|zone| zone == query.name())
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
                let lookup_result: Box<dyn LookupObject> = lookup_rx
                    .await
                    .unwrap_or_else(|_| Box::new(EmptyLookup) as Box<dyn LookupObject>);
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
        log::error!(
            "received a new request: {:?} from {:?}",
            request.message,
            request.src
        );
        if !request.src.ip().is_loopback() {
            log::error!("Dropping a stray request from outside: {}", request.src);
            return Box::pin(async {});
        }
        match request.message.message_type() {
            MessageType::Query => {
                match request.message.op_code() {
                    OpCode::Query => {
                        return Box::pin(self.lookup(request.message, response_handle));
                    }
                    OpCode::Update => {
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

async fn run_resolver_inner(
    command_sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
    done_tx: oneshot::Sender<mpsc::Sender<ResolverMessage>>,
) -> Result<(), String> {
    let (resolver, handle) = FilteringResolver::new(command_sender).await?;
    let resolver_handle = ResolverImpl { tx: handle.clone() };
    let mut server_future = ServerFuture::new(resolver_handle);
    let udp_sock = UdpSocket::bind("0.0.0.0:53")
        .await
        .map_err(|err| format!("{}", err))?;
    let tcp_sock = TcpListener::bind("0.0.0.0:53")
        .await
        .map_err(|err| format!("{}", err))?;
    server_future.register_socket(udp_sock);
    server_future.register_listener(tcp_sock, std::time::Duration::from_secs(1));
    let _ = done_tx.send(handle);

    tokio1::spawn(async move {
        resolver.run().await;
        log::error!("resolver stoppped");
    });
    server_future
        .block_until_done()
        .await
        .map_err(|err| format!("{}", err))
}
