// SPDX-License-Identifier: Apache-2.0
use spiffe::SpiffeId;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use time::OffsetDateTime;
use time::macros::format_description;
use tokio::sync::mpsc::{self, Receiver, Sender};

const QUEUE_CAPACITY: usize = 4096;
const BATCH_BYTES: usize = 32 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(10);
const ACCESS_LOG_TIME: &[time::format_description::BorrowedFormatItem<'_>] = format_description!(
    "[day]/[month repr:short]/[year]:[hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
);

pub struct Session {
    pub caller: SpiffeId,
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
}

pub enum Event {
    Open,
    End {
        status: &'static str,
        bytes: Option<(u64, u64)>,
        duration_ms: u128,
    },
}

struct SessionRecord {
    session: Arc<Session>,
    event: Event,
    timestamp: OffsetDateTime,
}

impl SessionRecord {
    fn write(self, batch: &mut Vec<u8>) -> io::Result<()> {
        let Session {
            caller,
            listen,
            upstream,
        } = self.session.as_ref();
        if matches!(self.event, Event::End { .. }) {
            batch.extend_from_slice(b"RESP: ");
        }
        write!(batch, "{caller} [")?;
        let timestamp_start = batch.len();
        if self.timestamp.format_into(batch, ACCESS_LOG_TIME).is_err() {
            batch.truncate(timestamp_start);
            batch.push(b'-');
        }
        match self.event {
            Event::Open => writeln!(
                batch,
                "] TCP connection_open listen={listen} upstream={upstream}"
            ),
            Event::End {
                status,
                bytes,
                duration_ms,
            } => {
                write!(batch, "] TCP {status} listen={listen} upstream={upstream}")?;
                if let Some((received, sent)) = bytes {
                    write!(batch, " received={received} sent={sent}")?;
                } else {
                    batch.extend_from_slice(b" received=- sent=-");
                }
                writeln!(batch, " {duration_ms}ms")
            }
        }
    }
}

enum Record {
    Session(SessionRecord),
    Diagnostic(String),
}

impl Record {
    fn write(self, batch: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Session(record) => record.write(batch),
            Self::Diagnostic(line) => writeln!(batch, "{line}"),
        }
    }
}

#[derive(Clone)]
pub struct AccessLog(Sender<Record>);

impl AccessLog {
    pub fn start() -> io::Result<(Self, JoinHandle<()>)> {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let writer = thread::Builder::new()
            .name("access-log".into())
            .spawn(move || write_batches(receiver))?;
        Ok((Self(sender), writer))
    }

    pub async fn record(&self, session: Arc<Session>, event: Event) {
        let _ = self
            .0
            .send(Record::Session(SessionRecord {
                session,
                event,
                timestamp: OffsetDateTime::now_utc(),
            }))
            .await;
    }

    pub fn diagnostic(&self, line: String) {
        let _ = self.0.try_send(Record::Diagnostic(line));
    }
}

fn write_batches(mut receiver: Receiver<Record>) {
    let mut batch = Vec::with_capacity(BATCH_BYTES);
    while let Some(record) = receiver.blocking_recv() {
        let _ = record.write(&mut batch);
        let mut waited = false;
        while batch.len() < BATCH_BYTES {
            match receiver.try_recv() {
                Ok(record) => {
                    let _ = record.write(&mut batch);
                }
                Err(mpsc::error::TryRecvError::Empty) if !waited => {
                    // Coalesce a short burst without a timer when the queue is idle.
                    thread::sleep(FLUSH_INTERVAL);
                    waited = true;
                }
                Err(_) => break,
            }
        }
        let _ = io::stderr().lock().write_all(&batch);
        batch.clear();
    }
}
