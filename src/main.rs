// SPDX-License-Identifier: Apache-2.0
mod access_log;
mod http;
mod tls;

use access_log::{AccessLog, Event, Session};
use arc_swap::ArcSwap;
use rustix::process::{Resource, getrlimit};
use serde::Deserialize;
use spiffe::{SpiffeId, cert::spiffe_id_from_der};
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::{self, ClientConfig, ServerConfig, pki_types::ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const USAGE: &str = "Usage: exordos-link CONFIG.json\n       exordos-link --version";
const ENDPOINT_PROTOCOL: &[u8] = b"exordos-endpoint/1";
const UPSTREAM_READY: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Tcp,
    Http,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    role: Role,
    listen: SocketAddr,
    targets: Vec<Target>,
    peer_ids: Vec<String>,
    protocol: Option<Protocol>,
    #[serde(default = "buffer_default")]
    buffer_bytes: usize,
    #[serde(default = "connect_default")]
    connect_timeout_ms: u64,
    #[serde(default = "health_default")]
    health_interval_ms: u64,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(untagged)]
enum Target {
    Address(SocketAddr),
    Scoped(ScopedTarget),
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ScopedTarget {
    address: SocketAddr,
    source: IpAddr,
}

impl Target {
    fn address(self) -> SocketAddr {
        match self {
            Self::Address(address) => address,
            Self::Scoped(target) => target.address,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listeners: Vec<Config>,
    #[serde(default = "connections_default")]
    max_connections: usize,
}

fn buffer_default() -> usize {
    16384
}
fn health_default() -> u64 {
    60_000
}
fn connect_default() -> u64 {
    200
}
fn connections_default() -> usize {
    4096
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.listen.port() == 0
            || self.listen.ip().is_unspecified()
            || self.targets.iter().any(|target| {
                let address = target.address();
                address.port() == 0
                    || address.ip().is_unspecified()
                    || matches!(target, Target::Scoped(scoped)
                        if self.role != Role::Outbound
                            || scoped.source.is_unspecified()
                            || scoped.source.is_ipv4() != address.is_ipv4())
            })
            || !(1024..=262144).contains(&self.buffer_bytes)
            || !(1..=60000).contains(&self.connect_timeout_ms)
            || !(10..=60000).contains(&self.health_interval_ms)
            || self.protocol.is_some() != (self.role == Role::Inbound)
            || (self.role == Role::Outbound && !self.listen.ip().is_loopback())
            || (self.role == Role::Inbound
                && (self.targets.len() != 1 || !self.targets[0].address().ip().is_loopback()))
        {
            return Err("invalid or unsafe proxy configuration".into());
        }
        Ok(())
    }
}

impl FileConfig {
    fn load(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let mut addresses = std::collections::HashSet::new();
        let mut protocols = HashMap::new();
        for listener in &config.listeners {
            listener.validate()?;
            if !addresses.insert(listener.listen) {
                return Err("duplicate listen address".into());
            }
            if let Some(protocol) = listener.protocol
                && let Some(previous) = protocols.insert(listener.targets[0].address(), protocol)
                && previous != protocol
            {
                return Err("application address cannot mix HTTP and TCP listeners".into());
            }
        }
        if !(1..=65536).contains(&config.max_connections) {
            return Err("invalid connection limit".into());
        }
        Ok(config)
    }
}

enum Tls {
    Server(Arc<ServerConfig>, AccessLog),
    Client(Arc<ClientConfig>),
}

struct Backend {
    target: Target,
    healthy: AtomicBool,
}

struct State {
    config: Config,
    tls: Tls,
    backends: Vec<Backend>,
    next: AtomicUsize,
    valid: AtomicBool,
    proxy_id: SpiffeId,
    allowed: Arc<BTreeSet<SpiffeId>>,
    generation: [u8; 32],
    tcp_sessions: Option<Arc<CancellationToken>>,
}

type TcpSessions = HashMap<SocketAddr, Weak<CancellationToken>>;

fn make_state(
    config: Config,
    credentials: &tls::Credentials,
    access_log: &AccessLog,
    tcp_sessions: &mut TcpSessions,
) -> Result<State> {
    let allowed = Arc::new(
        config
            .peer_ids
            .iter()
            .map(SpiffeId::new)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?,
    );
    let tls = match config.role {
        Role::Inbound => {
            let mut server = credentials.server()?;
            server.alpn_protocols = vec![ENDPOINT_PROTOCOL.to_vec()];
            Tls::Server(Arc::new(server), access_log.clone())
        }
        Role::Outbound => {
            let mut client = credentials.client(allowed.clone())?;
            client.alpn_protocols = vec![ENDPOINT_PROTOCOL.to_vec()];
            Tls::Client(Arc::new(client))
        }
    };
    let backends = config
        .targets
        .iter()
        .map(|target| Backend {
            target: *target,
            healthy: AtomicBool::new(true),
        })
        .collect();
    let tcp_sessions = (config.protocol == Some(Protocol::Tcp)).then(|| {
        let target = config.targets[0].address();
        if let Some(token) = tcp_sessions.get(&target).and_then(Weak::upgrade) {
            return token;
        }
        let token = Arc::new(CancellationToken::new());
        tcp_sessions.insert(target, Arc::downgrade(&token));
        token
    });
    Ok(State {
        config,
        tls,
        backends,
        next: AtomicUsize::new(0),
        valid: AtomicBool::new(true),
        proxy_id: credentials.id.clone(),
        allowed,
        generation: credentials.generation,
        tcp_sessions,
    })
}

async fn dial(target: Target) -> io::Result<TcpStream> {
    let socket = match target {
        Target::Address(address) => TcpStream::connect(address).await?,
        Target::Scoped(target) => {
            let socket = if target.source.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(target.source, 0))?;
            socket.connect(target.address).await?
        }
    };
    socket.set_nodelay(true)?;
    Ok(socket)
}

async fn serve(mut incoming: TcpStream, state: Arc<State>) -> Result<()> {
    incoming.set_nodelay(true)?;
    let limit = Duration::from_millis(state.config.connect_timeout_ms);
    let size = state.config.buffer_bytes;
    match &state.tls {
        Tls::Server(config, access_log) => {
            let started = Instant::now();
            let mut encrypted =
                timeout(limit, TlsAcceptor::from(config.clone()).accept(incoming)).await??;
            let peer_cert = encrypted
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or("authenticated connection missing peer certificate")?;
            if encrypted.get_ref().1.alpn_protocol() != Some(ENDPOINT_PROTOCOL) {
                return Err("endpoint protocol negotiation failed".into());
            }
            if !state.valid.load(Ordering::Acquire) {
                return Err("listener configuration changed before setup".into());
            }
            let caller = spiffe_id_from_der(peer_cert.as_ref())?;
            if !state.allowed.contains(&caller) {
                return Err("peer SPIFFE ID is not authorized for this endpoint".into());
            }
            let target = state.backends[0].target;
            let session = Arc::new(Session {
                caller,
                listen: state.config.listen,
                upstream: target.address(),
            });
            let xfcc = (state.config.protocol == Some(Protocol::Http))
                .then(|| http::peer_header(&state.proxy_id, &session.caller, peer_cert.as_ref()))
                .transpose()?;
            let (status, relayed) = match timeout(limit, dial(target)).await {
                Ok(Ok(mut local)) => {
                    if !state.valid.load(Ordering::Acquire) {
                        return Err("listener configuration changed before forwarding".into());
                    }
                    timeout(limit, async {
                        encrypted.write_u8(UPSTREAM_READY).await?;
                        encrypted.flush().await
                    })
                    .await??;
                    access_log.record(session.clone(), Event::Open).await;
                    let relayed = if let Some(header) = xfcc {
                        http::forward(encrypted, local, header, size).await
                    } else {
                        let copy =
                            copy_bidirectional_with_sizes(&mut encrypted, &mut local, size, size);
                        if let Some(sessions) = &state.tcp_sessions {
                            tokio::select! {
                                biased;
                                _ = sessions.cancelled() => Ok(None),
                                result = copy => result.map(Some).map_err(Into::into),
                            }
                        } else {
                            copy.await.map(Some).map_err(Into::into)
                        }
                    };
                    let status = if relayed.is_ok() { "ok" } else { "relay_error" };
                    (status, relayed)
                }
                Ok(Err(error)) => ("upstream_error", Err(error.into())),
                Err(error) => ("upstream_error", Err(error.into())),
            };
            access_log
                .record(
                    session,
                    Event::End {
                        status,
                        bytes: relayed.as_ref().ok().copied().flatten(),
                        duration_ms: started.elapsed().as_millis(),
                    },
                )
                .await;
            relayed?;
        }
        Tls::Client(config) => {
            let start = state.next.fetch_add(1, Ordering::Relaxed);
            let connector = TlsConnector::from(config.clone());
            let server_name = ServerName::try_from("spiffe.invalid")?;
            let mut connected = None;
            let mut deferred = std::collections::VecDeque::new();
            let mut candidates = (0..state.backends.len())
                .map(|offset| &state.backends[start.wrapping_add(offset) % state.backends.len()]);
            while let Some(backend) = candidates
                .find(|backend| {
                    if backend.healthy.load(Ordering::Relaxed) {
                        true
                    } else {
                        deferred.push_back(*backend);
                        false
                    }
                })
                .or_else(|| deferred.pop_front())
            {
                let connect = async {
                    let socket = dial(backend.target).await?;
                    let mut stream = connector.connect(server_name.clone(), socket).await?;
                    if stream.get_ref().1.alpn_protocol() != Some(ENDPOINT_PROTOCOL)
                        || stream.read_u8().await? != UPSTREAM_READY
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "endpoint did not confirm upstream readiness",
                        ));
                    }
                    Ok::<_, io::Error>(stream)
                };
                if let Ok(Ok(stream)) = timeout(limit, connect).await {
                    connected = Some(stream);
                    break;
                }
            }
            let mut encrypted = connected.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no authorized upstream available",
                )
            })?;
            if !state.valid.load(Ordering::Acquire) {
                return Err("listener configuration changed before forwarding".into());
            }
            copy_bidirectional_with_sizes(&mut incoming, &mut encrypted, size, size).await?;
        }
    }
    Ok(())
}

async fn health(state: Arc<ArcSwap<State>>, probes: Arc<Semaphore>) {
    loop {
        let current = state.load_full();
        if current.config.role == Role::Outbound {
            let limit = Duration::from_millis(current.config.connect_timeout_ms);
            let mut tasks = tokio::task::JoinSet::new();
            for (index, backend) in current.backends.iter().enumerate() {
                let current = current.clone();
                let target = backend.target;
                let probes = probes.clone();
                tasks.spawn(async move {
                    let _descriptor = probes
                        .acquire_owned()
                        .await
                        .expect("probe semaphore is open");
                    let healthy = matches!(timeout(limit, dial(target)).await, Ok(Ok(_)));
                    current.backends[index]
                        .healthy
                        .store(healthy, Ordering::Relaxed);
                });
            }
            while tasks.join_next().await.is_some() {}
        }
        sleep(Duration::from_millis(current.config.health_interval_ms)).await;
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let arg = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    match arg.as_os_str() {
        arg if arg == OsStr::new("--help") || arg == OsStr::new("-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        arg if arg == OsStr::new("--version") || arg == OsStr::new("-V") => {
            println!("exordos-link {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let path = PathBuf::from(arg);
    let config = FileConfig::load(&path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (access_log, writer) = AccessLog::start()?;
    let result = runtime.block_on(run(path, config, access_log));
    drop(runtime);
    writer.join().map_err(|_| "access log writer panicked")?;
    result
}

struct RunningListener {
    state: Arc<ArcSwap<State>>,
    task: JoinHandle<()>,
}

impl Drop for RunningListener {
    fn drop(&mut self) {
        self.state.load().valid.store(false, Ordering::Release);
        self.task.abort();
    }
}

async fn accept(
    listener: TcpListener,
    state: Arc<ArcSwap<State>>,
    capacity: Arc<Semaphore>,
    sockets: Arc<Semaphore>,
    access_log: AccessLog,
) {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                access_log.diagnostic(format!("accept blocked: {error}"));
                sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let Ok(descriptors) = sockets.clone().try_acquire_many_owned(2) else {
            continue;
        };
        let current = state.load_full();
        tokio::spawn(async move {
            let _permit = permit;
            let _descriptors = descriptors;
            let _ = serve(socket, current).await;
        });
    }
}

fn listener_states(
    config: FileConfig,
    credential_path: &Path,
    access_log: &AccessLog,
    tcp_sessions: &mut TcpSessions,
) -> Result<HashMap<SocketAddr, Arc<State>>> {
    if config.listeners.is_empty() {
        return Ok(HashMap::new());
    }
    let credentials = tls::Credentials::load(credential_path)?;
    config
        .listeners
        .into_iter()
        .map(|config| {
            let address = config.listen;
            let state = make_state(config, &credentials, access_log, tcp_sessions)?;
            Ok((address, Arc::new(state)))
        })
        .collect()
}

async fn open_listeners(
    running: &mut HashMap<SocketAddr, RunningListener>,
    wanted: &HashMap<SocketAddr, Arc<State>>,
    limit: &Arc<Semaphore>,
    sockets: &Arc<Semaphore>,
    probes: &Arc<Semaphore>,
    access_log: &AccessLog,
) {
    running.retain(|address, _| wanted.contains_key(address));
    for (address, listener) in running.iter() {
        let desired = &wanted[address];
        let current = listener.state.load();
        if current.config != desired.config || current.generation != desired.generation {
            let previous = listener.state.swap(desired.clone());
            previous.valid.store(false, Ordering::Release);
        }
    }
    for (&address, desired) in wanted {
        if running.contains_key(&address) {
            continue;
        }
        let Ok(mut descriptors) = sockets.clone().try_acquire_many_owned(3) else {
            access_log.diagnostic("listener waiting for available descriptors".into());
            break;
        };
        let descriptor = descriptors.split(1).expect("three descriptors reserved");
        drop(descriptors);
        let socket = match TcpListener::bind(address).await {
            Ok(socket) => socket,
            Err(error) => {
                access_log.diagnostic(format!("unable to listen on {address}: {error}"));
                continue;
            }
        };
        let state = Arc::new(ArcSwap::from(desired.clone()));
        let accept_state = state.clone();
        let health_state = state.clone();
        let limit = limit.clone();
        let sockets = sockets.clone();
        let probes = probes.clone();
        let log = access_log.clone();
        let task = tokio::spawn(async move {
            let _descriptor = descriptor;
            tokio::select! {
                _ = accept(socket, accept_state, limit, sockets.clone(), log) => {}
                _ = health(health_state, probes) => {}
            }
        });
        access_log.diagnostic(format!("ready {:?} {address}", desired.config.role));
        running.insert(address, RunningListener { state, task });
    }
}

async fn run(path: PathBuf, config: FileConfig, access_log: AccessLog) -> Result<()> {
    let capacity = config.max_connections;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider
        .install_default()
        .map_err(|_| "failed to set TLS crypto provider")?;
    let credential_path = std::env::var_os("EXORDOS_LINK_CREDENTIALS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/exordos/link/identity.pem"));
    let mut tcp_sessions = TcpSessions::new();
    let mut wanted = listener_states(config, &credential_path, &access_log, &mut tcp_sessions)?;
    // The FD reserve covers bounded health probes and other runtime descriptors.
    let descriptor_limit = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
    let descriptor_budget = descriptor_limit.saturating_sub(64);
    if descriptor_budget < 3 {
        return Err("RLIMIT_NOFILE leaves no capacity for proxied connections".into());
    }
    let sockets = Arc::new(Semaphore::new(
        descriptor_budget.min(Semaphore::MAX_PERMITS as u64) as usize,
    ));
    let capacity_limit = Arc::new(Semaphore::new(capacity));
    let probes = Arc::new(Semaphore::new(16));
    let mut reload = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut running = HashMap::new();
    open_listeners(
        &mut running,
        &wanted,
        &capacity_limit,
        &sockets,
        &probes,
        &access_log,
    )
    .await;
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = retry.tick(), if running.len() != wanted.len() => {
                open_listeners(
                    &mut running, &wanted, &capacity_limit, &sockets, &probes, &access_log,
                ).await;
                if running.len() == wanted.len() {
                    access_log.diagnostic("configuration applied".into());
                }
            }
            _ = reload.recv() => {
                let new = FileConfig::load(&path).and_then(|config| {
                    if config.max_connections != capacity {
                        return Err("changing capacity requires restart".into());
                    }
                    listener_states(config, &credential_path, &access_log, &mut tcp_sessions)
                });
                match new {
                    Ok(new) => {
                        for state in new.values().filter(|s| s.config.protocol == Some(Protocol::Http)) {
                            if let Some(token) = tcp_sessions
                                .remove(&state.config.targets[0].address())
                                .and_then(|token| token.upgrade())
                            {
                                token.cancel();
                            }
                        }
                        tcp_sessions.retain(|_, token| token.strong_count() > 0);
                        wanted = new;
                        open_listeners(
                            &mut running, &wanted, &capacity_limit, &sockets, &probes, &access_log,
                        ).await;
                        let status = if running.len() == wanted.len() {
                            "configuration applied"
                        } else {
                            "configuration loaded; retrying unavailable listeners"
                        };
                        access_log.diagnostic(status.into());
                    }
                    Err(error) => access_log.diagnostic(format!("configuration rejected: {error}")),
                }
            }
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
        }
    }
}
