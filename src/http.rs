// SPDX-License-Identifier: Apache-2.0
use crate::Result;
use http_body_util::{Either, Empty};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::upgrade::{self, OnUpgrade};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use sha2::{Digest, Sha256};
use spiffe::SpiffeId;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinSet;

const XFCC: &str = "x-forwarded-client-cert";
type Reply = Response<Either<Incoming, Empty<Bytes>>>;

pub fn peer_header(proxy: &SpiffeId, caller: &SpiffeId, leaf: &[u8]) -> Result<HeaderValue> {
    Ok(HeaderValue::from_str(&format!(
        "By={proxy};Hash={:x};URI={caller}",
        Sha256::digest(leaf)
    ))?)
}

fn remove_peer_header(headers: &mut HeaderMap) {
    headers.remove(XFCC);
    // WSGI environments can map underscores and dashes to the same key.
    let aliases: Vec<_> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str().as_bytes();
            name.len() == XFCC.len()
                && name.iter().zip(XFCC.bytes()).all(|(&actual, expected)| {
                    actual == expected || (actual == b'_' && expected == b'-')
                })
        })
        .cloned()
        .collect();
    for alias in aliases {
        headers.remove(alias);
    }
}

struct RequestBody(Incoming);

impl Body for RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.0).poll_frame(cx).map(|result| {
            result.map(|frame| {
                frame.map(|mut frame| {
                    if let Some(trailers) = frame.trailers_mut() {
                        remove_peer_header(trailers);
                    }
                    frame
                })
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

fn normalize_hop_headers(
    headers: &mut HeaderMap,
    version: Version,
    request: bool,
) -> Result<Option<HeaderValue>> {
    let mut encodings = headers.get_all(header::TRANSFER_ENCODING).iter();
    let chunked = if let Some(encoding) = encodings.next() {
        if version != Version::HTTP_11
            || !encoding.as_bytes().eq_ignore_ascii_case(b"chunked")
            || encodings.next().is_some()
        {
            return Err("unsupported HTTP transfer coding".into());
        }
        true
    } else {
        false
    };
    let tokens: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    let upgrade = (version == Version::HTTP_11 && tokens.contains(&header::UPGRADE))
        .then(|| headers.get(header::UPGRADE).cloned())
        .flatten();
    let close = tokens.iter().any(|name| name == "close");
    let trailers = request
        && matches!(version, Version::HTTP_11 | Version::HTTP_2)
        && headers
            .get(header::TE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"trailers"));
    for name in tokens {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
    ] {
        headers.remove(name);
    }
    if let Some(protocol) = &upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, protocol.clone());
    } else if close && version != Version::HTTP_2 {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    if trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        if version == Version::HTTP_11 {
            headers.append(header::CONNECTION, HeaderValue::from_static("TE"));
        }
    }
    if chunked {
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
    }
    Ok(upgrade)
}

enum Sender {
    Http1(http1::SendRequest<RequestBody>),
    Http2(http2::SendRequest<RequestBody>),
}

struct Backend {
    socket: Option<TcpStream>,
    sender: Option<Sender>,
    tasks: JoinSet<()>,
    closed: Arc<Notify>,
}

impl Backend {
    async fn sender(&mut self, version: Version) -> Result<&mut Sender> {
        if let Some(socket) = self.socket.take() {
            let io = TokioIo::new(socket);
            self.sender = Some(if version == Version::HTTP_2 {
                let (sender, connection) = http2::handshake(TokioExecutor::new(), io).await?;
                let closed = self.closed.clone();
                self.tasks.spawn(async move {
                    let _ = connection.await;
                    closed.notify_one();
                });
                Sender::Http2(sender)
            } else {
                let (sender, connection) = http1::handshake(io).await?;
                let closed = self.closed.clone();
                self.tasks.spawn(async move {
                    let _ = connection.with_upgrades().await;
                    closed.notify_one();
                });
                Sender::Http1(sender)
            });
        }
        self.sender
            .as_mut()
            .ok_or_else(|| "HTTP backend closed".into())
    }
}

struct HttpSession {
    backend: Mutex<Backend>,
    upgrade: Mutex<Option<(OnUpgrade, OnUpgrade)>>,
    xfcc: HeaderValue,
}

impl HttpSession {
    async fn request(&self, mut request: Request<Incoming>) -> Result<Reply> {
        if request.method() == Method::CONNECT {
            return Ok(empty_reply(StatusCode::METHOD_NOT_ALLOWED));
        }
        // Raw relay after a 101 must never become a second HTTP stream.
        if request
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|upgrade| !upgrade.as_bytes().eq_ignore_ascii_case(b"websocket"))
        {
            return Ok(empty_reply(StatusCode::BAD_REQUEST));
        }
        let version = request.version();
        let Ok(protocol) = normalize_hop_headers(request.headers_mut(), version, true) else {
            return Ok(empty_reply(StatusCode::BAD_REQUEST));
        };
        let downstream_upgrade = protocol.as_ref().map(|_| upgrade::on(&mut request));
        remove_peer_header(request.headers_mut());
        request.headers_mut().insert(XFCC, self.xfcc.clone());
        let request = request.map(RequestBody);
        let mut backend = self.backend.lock().await;
        let mut response = match backend.sender(version).await? {
            Sender::Http1(sender) => {
                sender.ready().await?;
                let response = sender.send_request(request);
                drop(backend);
                response.await?
            }
            Sender::Http2(sender) => {
                let mut sender = sender.clone();
                drop(backend);
                sender.send_request(request).await?
            }
        };
        let version = response.version();
        let selected = normalize_hop_headers(response.headers_mut(), version, false)?;
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let downstream = downstream_upgrade.ok_or("unexpected HTTP upgrade")?;
            if !matches!((protocol, selected), (Some(expected), Some(actual))
                if expected.as_bytes().eq_ignore_ascii_case(actual.as_bytes()))
            {
                return Err("unexpected HTTP upgrade protocol".into());
            }
            *self.upgrade.lock().await = Some((downstream, upgrade::on(&mut response)));
        }
        Ok(response.map(Either::Left))
    }
}

fn empty_reply(status: StatusCode) -> Reply {
    let mut response = Response::new(Either::Right(Empty::new()));
    *response.status_mut() = status;
    response
}

pub async fn forward(
    downstream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    socket: TcpStream,
    xfcc: HeaderValue,
    buffer: usize,
) -> Result<Option<(u64, u64)>> {
    let backend_closed = Arc::new(Notify::new());
    let session = Arc::new(HttpSession {
        backend: Mutex::new(Backend {
            socket: Some(socket),
            sender: None,
            tasks: JoinSet::new(),
            closed: backend_closed.clone(),
        }),
        upgrade: Mutex::new(None),
        xfcc,
    });
    let mut server = Builder::new(TokioExecutor::new());
    server.http1().timer(TokioTimer::new());
    let downstream = server.serve_connection_with_upgrades(
        TokioIo::new(downstream),
        service_fn({
            let session = session.clone();
            move |request| {
                let session = session.clone();
                async move {
                    let version = request.version();
                    let reply = session.request(request).await.unwrap_or_else(|_| {
                        let mut reply = empty_reply(StatusCode::BAD_GATEWAY);
                        if version != Version::HTTP_2 {
                            reply
                                .headers_mut()
                                .insert(header::CONNECTION, HeaderValue::from_static("close"));
                        }
                        reply
                    });
                    Ok::<_, Infallible>(reply)
                }
            }
        }),
    );
    tokio::pin!(downstream);
    tokio::select! {
        // An upstream upgrade may already have queued the downstream 101.
        biased;
        result = &mut downstream => result?,
        _ = backend_closed.notified() => {
            downstream.as_mut().graceful_shutdown();
            downstream.await?;
        }
    }
    let upgrade = session.upgrade.lock().await.take();
    if let Some((downstream, upstream)) = upgrade {
        let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
        return Ok(Some(
            copy_bidirectional_with_sizes(
                &mut TokioIo::new(downstream),
                &mut TokioIo::new(upstream),
                buffer,
                buffer,
            )
            .await?,
        ));
    }
    Ok(None)
}
