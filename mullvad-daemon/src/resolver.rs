use trust_dns_proto::{
    error::ProtoError,
    iocompat::AsyncIoTokioAsStd,
    op::{header::MessageType, op_code::OpCode, Header, NoopMessageFinalizer},
    rr::{domain::Name, record_data::RData, Record},
    tcp::{Connect, DnsTcpStream, TcpClientStream},
    udp::{UdpClientStream, UdpSocket},
    xfer::{DnsExchange, DnsRequest, DnsResponse},
    DnsHandle, DnsMultiplexer, TokioTime,
};

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

#[cfg(target_os = "macos")]
use std::{
    net,
    num::NonZeroU32,
    os::unix::io::{FromRawFd, IntoRawFd, RawFd},
};

use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    SinkExt, StreamExt,
};
use tokio1::runtime::Runtime;

use trust_dns_client::{
    op::{LowerQuery, Query},
    rr::{LowerName, RecordType},
};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveError,
    lookup::Lookup,
    name_server::{self, GenericConnection, GenericConnectionProvider, TokioHandle},
    AsyncResolver, ConnectionProvider, TokioAsyncResolver,
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
    resolver_config: ResolverConfig,
    regular_resolver: RegularUpstreamResolver,
    excluded_resolver: ExcludedUpstreamResolver,
    rx: mpsc::Receiver<ResolverMessage>,
    filtering_state: FilteringState,
    command_sender: mpsc::Sender<(Vec<IpAddr>, oneshot::Sender<()>)>,
}

type OurConnectionProvider = GenericConnectionProvider<RuntimeProvider>;
type ExcludedUpstreamResolver = AsyncResolver<GenericConnection, OurConnectionProvider>;
type RegularUpstreamResolver = TokioAsyncResolver;

#[derive(Debug, PartialEq, Clone)]
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

        let resolver_config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["193.138.218.74".parse().unwrap()], 53, false),
        );
        let excluded_resolver = ExcludedUpstreamResolver::new(
            resolver_config.clone(),
            ResolverOpts::default(),
            TokioHandle,
        )
        .map_err(|err| format!("{}", err))?;
        let regular_resolver =
            RegularUpstreamResolver::tokio(resolver_config.clone(), ResolverOpts::default())
                .map_err(|err| format!("{}", err))?;

        Ok((
            Self {
                allowed_zones: vec![
                    LowerName::from(Name::from_str("ntp.apple.com").unwrap()),
                    LowerName::from(Name::from_str("apple.com").unwrap()),
                    LowerName::from(Name::from_str("www.apple.com").unwrap()),
                ],
                resolver_config,
                excluded_resolver,
                regular_resolver,
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
                    let resolver_config = ResolverConfig::from_parts(
                        None,
                        vec![],
                        NameServerConfigGroup::from_ips_clear(&resolvers, 53, false),
                    );
                    match AsyncResolver::new(
                        resolver_config.clone(),
                        ResolverOpts::default(),
                        TokioHandle,
                    ) {
                        Ok(resolver) => {
                            log::debug!("Using new resolver config: {:?}", resolver_config);
                            self.resolver_config = resolver_config;
                            self.excluded_resolver = resolver;
                        }
                        Err(err) => {
                            log::error!("Failed to apply new resolver config: {}", err);
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
            log::debug!("Blocking query {}", query);
            let _ = tx.send(empty_response);
            return Either::Left(async {});
        }

        log::debug!("Will try to resolve {}", query);
        let mut unblock_tx = self.command_sender.clone();
        let lookup: Box<dyn Future<Output = Result<Lookup, ResolveError>> + Unpin + Send> =
            if self.filtering_state == FilteringState::On {
                Box::new(self.excluded_resolver.lookup(
                    query.name().clone(),
                    RecordType::A,
                    Default::default(),
                ))
            } else {
                Box::new(self.regular_resolver.lookup(
                    query.name().clone(),
                    RecordType::A,
                    Default::default(),
                ))
            };
        let filtering_state = self.filtering_state.clone();
        Either::Right(async move {
            match lookup.await {
                Ok(result) => {
                    let lookup = ForwardLookup(result);
                    let ip_records = lookup
                        .iter()
                        .filter_map(|record| match record.rdata() {
                            RData::A(ipv4) => Some(IpAddr::from(*ipv4)),
                            RData::AAAA(ipv6) => Some(IpAddr::from(*ipv6)),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if !ip_records.is_empty() {
                        log::error!("Successfully resolved {:?} to {:?}", query, ip_records);
                        if filtering_state == FilteringState::On {
                            let (done_tx, done_rx) = oneshot::channel();
                            if unblock_tx.send((ip_records, done_tx)).await.is_ok() {
                                let _ = done_rx.await;
                            } else {
                                log::error!("Failed to send IPs to unblocker");
                            }
                        }
                    }
                    if tx.send(Box::new(lookup)).is_err() {
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
    let udp_sock = tokio1::net::UdpSocket::bind("0.0.0.0:53")
        .await
        .map_err(|err| format!("{}", err))?;
    let tcp_sock = tokio1::net::TcpListener::bind("0.0.0.0:53")
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

#[derive(Clone)]
struct SocketBinder {}

#[derive(Clone)]
struct RuntimeProvider {}

impl name_server::RuntimeProvider for RuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = OwnSock;
    type Tcp = OwnTcpSock;
}

#[derive(Debug)]
struct OwnSock {
    socket: tokio1::net::UdpSocket,
}

impl OwnSock {
    #[cfg(target_os = "macos")]
    async fn inner_bind(addr: SocketAddr) -> io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let raw_fd: RawFd = tokio1::task::spawn_blocking(move || -> io::Result<RawFd> {
            let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_nonblocking(true)?;
            match best_interface() {
                Some(iface_index) => {
                    if let Err(err) =  socket.bind_device_by_index(Some(iface_index)) {
                        log::error!("FAILED TO BIND SOCKET TO DEVICE: {}", err);
                        return Err(err);
                    }
                },
                None => {
                    log::error!("FAILED TO GET INTERFACE INDEX");
                },
            };
            Ok(socket.into_raw_fd())
        })
        .await??;
        let std_socket = unsafe { net::UdpSocket::from_raw_fd(raw_fd) };
        let socket = tokio1::net::UdpSocket::from_std(std_socket)?;
        Ok(OwnSock { socket })
    }


}

#[cfg(target_os = "macos")]
fn best_interface() -> Option<NonZeroU32> {
    let best_interface = b"en0\0";
    NonZeroU32::new(unsafe { libc::if_nametoindex(best_interface.as_ptr() as *const _) })
}

#[async_trait::async_trait]
impl UdpSocket for OwnSock {
    type Time = TokioTime;

    async fn bind(addr: SocketAddr) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let result = Self::inner_bind(addr).await;
            log::trace!("bind result: {:?}", result);
            result
        }
        #[cfg(not(target_os = "macos"))]
        {
            let socket = tokio1::net::UdpSocket::bind(addr).await?;
            Ok(OwnSock { socket })
        }
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buf = tokio1::io::ReadBuf::new(buf);
        let addr = futures::ready!(tokio1::net::UdpSocket::poll_recv_from(
            &self.socket,
            cx,
            &mut buf
        ))?;
        let len = buf.filled().len();

        Poll::Ready(Ok((len, addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        tokio1::net::UdpSocket::poll_send_to(&self.socket, cx, buf, target)
    }
}

struct OwnTcpSock {
    stream: tokio1::net::TcpStream,
}

use tokio1::io::AsyncRead;
impl futures::io::AsyncRead for OwnTcpSock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = tokio1::io::ReadBuf::new(buf);
        futures::ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
        Poll::Ready(Ok(read_buf.filled().len()))
    }
}

use tokio1::io::AsyncWrite;
impl tokio1::io::AsyncWrite for OwnTcpSock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl futures::io::AsyncWrite for OwnTcpSock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl tokio1::io::AsyncRead for OwnTcpSock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio1::io::ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl DnsTcpStream for OwnTcpSock {
    type Time = TokioTime;
}

impl OwnTcpSock {
    #[cfg(target_os = "macos")]
    async fn inner_bind(addr: SocketAddr) -> io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let raw_fd: RawFd = tokio1::task::spawn_blocking(move || -> io::Result<RawFd> {
            let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
            socket.set_nonblocking(true)?;
            match best_interface() {
                Some(iface_index) => {
                    if let Err(err) =  socket.bind_device_by_index(Some(iface_index)) {
                        log::error!("FAILED TO BIND SOCKET TO DEVICE: {}", err);
                        return Err(err);
                    }
                },
                None => {
                    log::error!("FAILED TO GET INTERFACE INDEX");
                },
            };
            Ok(socket.into_raw_fd())
        })
        .await??;
        let socket = unsafe { tokio1::net::TcpSocket::from_raw_fd(raw_fd) };
        let stream = socket.connect(addr).await?;


        Ok(Self { stream })
    }
}

#[async_trait::async_trait]
impl Connect for OwnTcpSock {
    async fn connect(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            stream: tokio1::net::TcpStream::connect(addr).await?,
        })
    }
}

pub struct ForwardLookup(Lookup);

/// This trait has to be reimplemented for the Lookup so that it can be sent back to the
/// RequestHandler implementation.
impl LookupObject for ForwardLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.record_iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
