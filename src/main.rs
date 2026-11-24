// SPDX-License-Identifier: Apache-2.0
mod access_log;

use access_log::{AccessLog, Event, Session};
use arc_swap::ArcSwap;
use rustix::process::{Resource, getrlimit};
use serde::Deserialize;
use spiffe::{X509Source, cert::spiffe_id_from_der};
use spiffe_rustls::{authorizer, mtls_client, mtls_server};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::{self, ClientConfig, ServerConfig, pki_types::ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    role: Role,
    listen: SocketAddr,
    targets: Vec<Target>,
    peer_ids: Vec<String>,
    #[serde(default = "buffer_default")]
    buffer_bytes: usize,
    #[serde(default = "connect_default")]
    connect_timeout_ms: u64,
    #[serde(default = "health_default")]
    health_interval_ms: u64,
    max_connections: Option<usize>,
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
struct ManagedConfig {
    listeners: Vec<Config>,
    #[serde(default = "connections_default")]
    max_connections: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FileConfig {
    Legacy(Config),
    Managed(ManagedConfig),
}

fn buffer_default() -> usize {
    16384
}
fn health_default() -> u64 {
    250
}
fn connect_default() -> u64 {
    200
}
fn connections_default() -> usize {
    4096
}

impl Config {
    fn validate(&self, managed: bool) -> Result<()> {
        if self.listen.port() == 0
            || (managed && self.listen.ip().is_unspecified())
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
            || (managed && self.max_connections.is_some())
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
        for listener in config.listeners() {
            listener.validate(config.managed())?;
            if !addresses.insert(listener.listen) {
                return Err("duplicate listen address".into());
            }
        }
        if !(1..=65536).contains(&config.max_connections()) {
            return Err("invalid connection limit".into());
        }
        Ok(config)
    }

    fn managed(&self) -> bool {
        matches!(self, Self::Managed(_))
    }

    fn listeners(&self) -> &[Config] {
        match self {
            Self::Legacy(config) => std::slice::from_ref(config),
            Self::Managed(config) => &config.listeners,
        }
    }

    fn max_connections(&self) -> usize {
        match self {
            Self::Legacy(config) => config.max_connections.unwrap_or_else(connections_default),
            Self::Managed(config) => config.max_connections,
        }
    }

    fn into_listeners(self) -> Vec<Config> {
        match self {
            Self::Legacy(config) => vec![config],
            Self::Managed(config) => config.listeners,
        }
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
    managed: bool,
    valid: AtomicBool,
}

fn make_state(
    config: Config,
    managed: bool,
    source: X509Source,
    access_log: Option<&AccessLog>,
) -> Result<State> {
    let authorizer = authorizer::exact(config.peer_ids.iter().map(String::as_str))?;
    let tls = match config.role {
        Role::Inbound => {
            let mut server = mtls_server(source).authorize(authorizer).build()?;
            if managed {
                server.alpn_protocols = vec![ENDPOINT_PROTOCOL.to_vec()];
            }
            let log = access_log.ok_or("missing inbound access log")?;
            Tls::Server(Arc::new(server), log.clone())
        }
        Role::Outbound => {
            let mut client = mtls_client(source).authorize(authorizer).build()?;
            if managed {
                client.alpn_protocols = vec![ENDPOINT_PROTOCOL.to_vec()];
            }
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
    Ok(State {
        config,
        tls,
        backends,
        next: AtomicUsize::new(0),
        managed,
        valid: AtomicBool::new(true),
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
            if state.managed && encrypted.get_ref().1.alpn_protocol() != Some(ENDPOINT_PROTOCOL) {
                return Err("endpoint protocol negotiation failed".into());
            }
            if !state.valid.load(Ordering::Acquire) {
                return Err("listener configuration changed before setup".into());
            }
            let target = state.backends[0].target;
            let session = Arc::new(Session {
                caller: spiffe_id_from_der(peer_cert.as_ref())?,
                listen: state.config.listen,
                upstream: target.address(),
            });
            let (status, relayed) = match timeout(limit, dial(target)).await {
                Ok(Ok(mut local)) => {
                    if !state.valid.load(Ordering::Acquire) {
                        return Err("listener configuration changed before forwarding".into());
                    }
                    if state.managed {
                        timeout(limit, async {
                            encrypted.write_u8(UPSTREAM_READY).await?;
                            encrypted.flush().await
                        })
                        .await??;
                    }
                    access_log.record(session.clone(), Event::Open).await;
                    let relayed =
                        copy_bidirectional_with_sizes(&mut encrypted, &mut local, size, size).await;
                    let status = if relayed.is_ok() { "ok" } else { "relay_error" };
                    (status, relayed)
                }
                Ok(Err(error)) => ("upstream_error", Err(error)),
                Err(error) => ("upstream_error", Err(error.into())),
            };
            access_log
                .record(
                    session,
                    Event::End {
                        status,
                        bytes: relayed.as_ref().ok().copied(),
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
            for offset in 0..state.backends.len() {
                let backend = &state.backends[start.wrapping_add(offset) % state.backends.len()];
                if !backend.healthy.load(Ordering::Relaxed) {
                    continue;
                }
                let connect = async {
                    let socket = dial(backend.target).await?;
                    let mut stream = connector.connect(server_name.clone(), socket).await?;
                    if state.managed
                        && (stream.get_ref().1.alpn_protocol() != Some(ENDPOINT_PROTOCOL)
                            || stream.read_u8().await? != UPSTREAM_READY)
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
                    let _descriptor = if current.managed {
                        Some(
                            probes
                                .acquire_owned()
                                .await
                                .expect("probe semaphore is open"),
                        )
                    } else {
                        None
                    };
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
    let (access_log, writer) = if config.managed() || config.listeners()[0].role == Role::Inbound {
        let (access_log, writer) = AccessLog::start()?;
        (Some(access_log), Some(writer))
    } else {
        (None, None)
    };
    let result = runtime.block_on(run(path, config, access_log));
    drop(runtime);
    if let Some(writer) = writer {
        writer.join().map_err(|_| "access log writer panicked")?;
    }
    result
}

fn runtime_diagnostic(access_log: Option<&AccessLog>, line: String) {
    if let Some(access_log) = access_log {
        access_log.diagnostic(line);
    } else {
        eprintln!("{line}");
    }
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
    access_log: Option<AccessLog>,
) {
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                runtime_diagnostic(access_log.as_ref(), format!("accept blocked: {error}"));
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
    source: &X509Source,
    access_log: Option<&AccessLog>,
) -> Result<HashMap<SocketAddr, Arc<State>>> {
    let managed = config.managed();
    config
        .into_listeners()
        .into_iter()
        .map(|config| {
            let address = config.listen;
            let state = make_state(config, managed, source.clone(), access_log)?;
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
    access_log: Option<&AccessLog>,
    managed: bool,
) -> Result<()> {
    running.retain(|address, _| wanted.contains_key(address));
    for (address, listener) in running.iter() {
        let desired = &wanted[address];
        if listener.state.load().config != desired.config {
            let previous = listener.state.swap(desired.clone());
            previous.valid.store(false, Ordering::Release);
        }
    }
    for (&address, desired) in wanted {
        if running.contains_key(&address) {
            continue;
        }
        let Ok(mut descriptors) = sockets.clone().try_acquire_many_owned(3) else {
            runtime_diagnostic(
                access_log,
                "listener waiting for available descriptors".into(),
            );
            break;
        };
        let descriptor = descriptors.split(1).expect("three descriptors reserved");
        drop(descriptors);
        let socket = match TcpListener::bind(address).await {
            Ok(socket) => socket,
            Err(error) if managed => {
                runtime_diagnostic(
                    access_log,
                    format!("unable to listen on {address}: {error}"),
                );
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let state = Arc::new(ArcSwap::from(desired.clone()));
        let accept_state = state.clone();
        let health_state = state.clone();
        let limit = limit.clone();
        let sockets = sockets.clone();
        let probes = probes.clone();
        let log = access_log.cloned();
        let task = tokio::spawn(async move {
            let _descriptor = descriptor;
            tokio::select! {
                _ = accept(socket, accept_state, limit, sockets.clone(), log) => {}
                _ = health(health_state, probes) => {}
            }
        });
        runtime_diagnostic(
            access_log,
            format!("ready {:?} {address}", desired.config.role),
        );
        running.insert(address, RunningListener { state, task });
    }
    Ok(())
}

async fn run(path: PathBuf, config: FileConfig, access_log: Option<AccessLog>) -> Result<()> {
    let managed = config.managed();
    let capacity = config.max_connections();
    let legacy_listener = (!managed).then(|| {
        let config = &config.listeners()[0];
        (config.listen, config.role)
    });
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider
        .install_default()
        .map_err(|_| "failed to set TLS crypto provider")?;
    let source = X509Source::new().await?;
    let mut wanted = listener_states(config, &source, access_log.as_ref())?;
    // The FD reserve covers Workload API and bounded managed health probes.
    // Legacy configuration also counts its sole listener in that reserve.
    let descriptor_limit = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
    let descriptor_budget = descriptor_limit.saturating_sub(if managed { 64 } else { 63 });
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
        access_log.as_ref(),
        managed,
    )
    .await?;
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = retry.tick(), if running.len() != wanted.len() => {
                open_listeners(
                    &mut running, &wanted, &capacity_limit, &sockets, &probes, access_log.as_ref(), managed,
                ).await?;
                if running.len() == wanted.len() {
                    runtime_diagnostic(access_log.as_ref(), "configuration applied".into());
                }
            }
            _ = reload.recv() => {
                let new = FileConfig::load(&path).and_then(|config| {
                    if config.managed() != managed || config.max_connections() != capacity
                        || legacy_listener.is_some_and(|current| {
                            let next = &config.listeners()[0];
                            current != (next.listen, next.role)
                        })
                    {
                        return Err("changing mode, legacy listener or capacity requires restart".into());
                    }
                    listener_states(config, &source, access_log.as_ref())
                });
                match new {
                    Ok(new) => {
                        wanted = new;
                        open_listeners(
                            &mut running, &wanted, &capacity_limit, &sockets, &probes, access_log.as_ref(), managed,
                        ).await?;
                        let status = if running.len() == wanted.len() {
                            "configuration applied"
                        } else {
                            "configuration loaded; retrying unavailable listeners"
                        };
                        runtime_diagnostic(access_log.as_ref(), status.into());
                    }
                    Err(error) => runtime_diagnostic(access_log.as_ref(), format!("configuration rejected: {error}")),
                }
            }
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
        }
    }
}
