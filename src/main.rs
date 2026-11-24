// SPDX-License-Identifier: Apache-2.0
mod access_log;

use access_log::{AccessLog, Event, Session};
use arc_swap::ArcSwap;
use rustix::process::{Resource, getrlimit};
use serde::Deserialize;
use spiffe::{X509Source, cert::spiffe_id_from_der};
use spiffe_rustls::{authorizer, mtls_client, mtls_server};
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::{self, ClientConfig, ServerConfig, pki_types::ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const USAGE: &str = "Usage: exordos-link CONFIG.json\n       exordos-link --version";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Inbound,
    Outbound,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    role: Role,
    listen: SocketAddr,
    targets: Vec<SocketAddr>,
    peer_ids: Vec<String>,
    #[serde(default = "buffer_default")]
    buffer_bytes: usize,
    #[serde(default = "connect_default")]
    connect_timeout_ms: u64,
    #[serde(default = "health_default")]
    health_interval_ms: u64,
    #[serde(default = "connections_default")]
    max_connections: usize,
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
    fn load(path: &Path) -> Result<Self> {
        let cfg: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        if cfg.listen.port() == 0
            || cfg
                .targets
                .iter()
                .any(|addr| addr.port() == 0 || addr.ip().is_unspecified())
            || !(1024..=262144).contains(&cfg.buffer_bytes)
            || !(1..=60000).contains(&cfg.connect_timeout_ms)
            || !(10..=60000).contains(&cfg.health_interval_ms)
            || !(1..=65536).contains(&cfg.max_connections)
            || (cfg.role == Role::Outbound && !cfg.listen.ip().is_loopback())
            || (cfg.role == Role::Inbound
                && (cfg.targets.len() != 1 || !cfg.targets[0].ip().is_loopback()))
        {
            return Err("invalid or unsafe proxy configuration".into());
        }
        Ok(cfg)
    }
}

enum Tls {
    Server(Arc<ServerConfig>, AccessLog),
    Client(Arc<ClientConfig>),
}

struct Backend {
    address: SocketAddr,
    healthy: AtomicBool,
}

struct State {
    config: Config,
    tls: Tls,
    backends: Vec<Backend>,
    next: AtomicUsize,
}

fn make_state(config: Config, source: X509Source, access_log: Option<&AccessLog>) -> Result<State> {
    let authorizer = authorizer::exact(config.peer_ids.iter().map(String::as_str))?;
    let tls = match config.role {
        Role::Inbound => {
            let server = mtls_server(source).authorize(authorizer).build()?;
            let log = access_log.ok_or("missing inbound access log")?;
            Tls::Server(Arc::new(server), log.clone())
        }
        Role::Outbound => {
            let client = mtls_client(source).authorize(authorizer).build()?;
            Tls::Client(Arc::new(client))
        }
    };
    let backends = config
        .targets
        .iter()
        .map(|address| Backend {
            address: *address,
            healthy: AtomicBool::new(true),
        })
        .collect();
    Ok(State {
        config,
        tls,
        backends,
        next: AtomicUsize::new(0),
    })
}

async fn dial(address: SocketAddr, limit: Duration) -> io::Result<TcpStream> {
    let socket = timeout(limit, TcpStream::connect(address)).await??;
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
            let target = state.backends[0].address;
            let session = Arc::new(Session {
                caller: spiffe_id_from_der(peer_cert.as_ref())?,
                listen: state.config.listen,
                upstream: target,
            });
            let (status, relayed) = match dial(target, limit).await {
                Ok(mut local) => {
                    access_log.record(session.clone(), Event::Open).await;
                    let relayed =
                        copy_bidirectional_with_sizes(&mut encrypted, &mut local, size, size).await;
                    let status = if relayed.is_ok() { "ok" } else { "relay_error" };
                    (status, relayed)
                }
                Err(error) => ("upstream_error", Err(error)),
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
                    let socket = dial(backend.address, limit).await?;
                    connector.connect(server_name.clone(), socket).await
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
            copy_bidirectional_with_sizes(&mut incoming, &mut encrypted, size, size).await?;
        }
    }
    Ok(())
}

async fn health(state: Arc<ArcSwap<State>>) {
    loop {
        let current = state.load_full();
        if current.config.role == Role::Outbound {
            let limit = Duration::from_millis(current.config.connect_timeout_ms);
            let mut tasks = tokio::task::JoinSet::new();
            for (index, backend) in current.backends.iter().enumerate() {
                let current = current.clone();
                let address = backend.address;
                tasks.spawn(async move {
                    let healthy = dial(address, limit).await.is_ok();
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
    let config = Config::load(&path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (access_log, writer) = match config.role {
        Role::Inbound => {
            let (access_log, writer) = AccessLog::start()?;
            (Some(access_log), Some(writer))
        }
        Role::Outbound => (None, None),
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

async fn run(path: PathBuf, config: Config, access_log: Option<AccessLog>) -> Result<()> {
    let (address, role, capacity) = (config.listen, config.role, config.max_connections);
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider
        .install_default()
        .map_err(|_| "failed to set TLS crypto provider")?;
    let source = X509Source::new().await?;
    let state = Arc::new(ArcSwap::from_pointee(make_state(
        config,
        source.clone(),
        access_log.as_ref(),
    )?));
    let listener = TcpListener::bind(address).await?;
    // Each accepted stream may open a second socket for the relay. Keep a
    // descriptor reserve for the listener, Workload API, and probes.
    let descriptor_limit = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
    let sockets = descriptor_limit.saturating_sub(64) / 2;
    let effective_capacity = (capacity as u64).min(sockets) as usize;
    if effective_capacity == 0 {
        return Err("RLIMIT_NOFILE leaves no capacity for proxied connections".into());
    }
    let capacity_limit = Arc::new(Semaphore::new(effective_capacity));
    let mut reload = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::spawn(health(state.clone()));
    eprintln!("ready {role:?} {address}, max_connections={effective_capacity}");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        runtime_diagnostic(access_log.as_ref(), format!("accept blocked: {error}"));
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = capacity_limit.clone().try_acquire_owned() else { continue };
                let current = state.load_full();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve(socket, current).await;
                });
            }
            _ = reload.recv() => {
                let new = Config::load(&path).and_then(|config| {
                    if (config.listen, config.role, config.max_connections) != (address, role, capacity) {
                        return Err("changing listen, role or capacity requires restart".into());
                    }
                    make_state(config, source.clone(), access_log.as_ref())
                });
                match new {
                    Ok(new) => {
                        state.store(Arc::new(new));
                        runtime_diagnostic(access_log.as_ref(), "configuration applied".into());
                    }
                    Err(error) => runtime_diagnostic(access_log.as_ref(), format!("configuration rejected: {error}")),
                }
            }
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
        }
    }
}
