// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::outbound::UdpUpstream;
use crate::resolver::Resolver;
use crate::runtime::SharedState;
use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;
use sb_outbound::direct::bind_udp_socket;
use sb_outbound::socks5_udp::{
    decode_udp_reply, encode_udp_request_domain_into, encode_udp_request_into, udp_associate_auth,
};
use sb_sniff::quic;
use sb_stats::ConnRecord;
use sb_stats::types::{InboundKind, SniffedProto as StatProto, Transport};
use sb_tproxy::spoof_cache::SpoofCache;
use sb_tproxy::udp::{
    MMSG_SLOT_CAP, MMSG_VLEN, MmsgBuf, MmsgRxBuf, TproxyUdp, bind_tproxy_udp,
    recv_mmsg_payloads_nonblocking, send_mmsg_to,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, Interest};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Copy, Clone, Debug)]
enum FlowKind {
    Symmetric,
    Fullcone,
}

const REPLY_SLOT_CAP: usize = 4096;

const PENDING_QUEUE_CAP: usize = 8;

struct Pending<T> {

    queue: Mutex<Option<Vec<T>>>,

    created_ms: u64,
}

impl<T> Pending<T> {
    fn new(first: T, now_ms: u64) -> Self {
        Self {
            queue: Mutex::new(Some(vec![first])),
            created_ms: now_ms,
        }
    }
    fn push(&self, item: T) {
        if let Some(q) = self.queue.lock().as_mut()
            && q.len() < PENDING_QUEUE_CAP
        {
            q.push(item);
        }
    }
    fn take(&self) -> Vec<T> {
        self.queue.lock().take().unwrap_or_default()
    }
    fn close(&self) {
        *self.queue.lock() = None;
    }
}

#[derive(Clone)]
enum SymSlot {
    Pending(Arc<Pending<Vec<u8>>>),
    Ready(Arc<SymmetricSession>),
}

#[derive(Clone)]
enum FcSlot {
    Pending(Arc<Pending<(SocketAddr, Vec<u8>)>>),
    Ready(Arc<FullconeSession>),
}

pub struct SymmetricSession {
    relay_udp: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    last_seen_ms: AtomicU64,

    routing_host: ArcSwapOption<String>,

    sniff_done: AtomicBool,
    quic_sniffer: Mutex<Option<quic::IncrementalSniffer>>,

    fakeip_host: Option<String>,

    is_fakeip: bool,

    direct: bool,

    rec: Arc<ConnRecord>,
}

impl Drop for SymmetricSession {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub struct FullconeSession {
    relay_udp: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    last_seen_ms: AtomicU64,

    direct: bool,

    rec: Arc<ConnRecord>,
}

impl Drop for FullconeSession {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub struct UdpEngine {

    symmetric: Arc<DashMap<(SocketAddr, SocketAddr), SymSlot>>,

    fullcone: Arc<DashMap<SocketAddr, FcSlot>>,

    flow_path: Arc<DashMap<(SocketAddr, SocketAddr), FlowEntry>>,
    spoof_cache: Arc<SpoofCache>,
    started: Instant,
    pub idle_timeout: Duration,

    pub pkts_fwd_sym: AtomicU64,
    pub pkts_fwd_fc: AtomicU64,
    pub pkts_reply_sym: AtomicU64,
    pub pkts_reply_fc: AtomicU64,
}

struct FlowEntry {
    kind: FlowKind,
    last_seen_ms: AtomicU64,
}

impl UdpEngine {
    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn len(&self) -> usize {
        self.symmetric.len() + self.fullcone.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symmetric.is_empty() && self.fullcone.is_empty()
    }
}

pub fn start_udp_engine(
    shared: Arc<SharedState>,
    listen_addr: SocketAddr,
    idle_timeout: Duration,
    workers: usize,
    spoof_cache_cap: usize,
    shutdown_rx: watch::Receiver<bool>,
) -> io::Result<Arc<UdpEngine>> {

    let udp_bind_addr = match listen_addr {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], listen_addr.port())),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], listen_addr.port())),
    };

    let workers = workers.max(1);

    let first = bind_tproxy_udp(udp_bind_addr)?;
    let mut listeners: Vec<Arc<TproxyUdp>> = vec![Arc::new(first)];
    for _ in 1..workers {
        match bind_tproxy_udp(udp_bind_addr) {
            Ok(l) => listeners.push(Arc::new(l)),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "additional UDP REUSEPORT bind failed; falling back to fewer workers"
                );
                break;
            }
        }
    }
    tracing::info!(
        bind = %udp_bind_addr, configured = %listen_addr, workers = listeners.len(),
        mmsg_vlen = MMSG_VLEN,
        "tproxy udp listening (REUSEPORT multi-worker + recvmmsg)"
    );

    let engine = Arc::new(UdpEngine {
        symmetric: Arc::new(DashMap::new()),
        fullcone: Arc::new(DashMap::new()),
        flow_path: Arc::new(DashMap::new()),
        spoof_cache: Arc::new(SpoofCache::new(spoof_cache_cap)),
        started: Instant::now(),
        idle_timeout,
        pkts_fwd_sym: AtomicU64::new(0),
        pkts_fwd_fc: AtomicU64::new(0),
        pkts_reply_sym: AtomicU64::new(0),
        pkts_reply_fc: AtomicU64::new(0),
    });

    {
        let engine = Arc::clone(&engine);
        let shared = Arc::clone(&shared);
        let mut sd = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_fwd_sym: u64 = 0;
            let mut last_fwd_fc: u64 = 0;
            let mut last_reply_sym: u64 = 0;
            let mut last_reply_fc: u64 = 0;
            loop {
                tokio::select! {
                    biased;
                    _ = sd.changed() => { if *sd.borrow() { break; } }
                    _ = ticker.tick() => {
                        let (sym_rm, fc_rm, fp_rm) = sweep_idle(&engine, &shared);
                        if sym_rm + fc_rm + fp_rm > 0 {
                            tracing::debug!(symmetric_removed=sym_rm, fullcone_removed=fc_rm, flow_path_removed=fp_rm,
                                alive=engine.len(), spoof_cached=engine.spoof_cache.len(), "udp idle sweep");
                        }
                        let fwd_sym = engine.pkts_fwd_sym.load(Ordering::Relaxed);
                        let fwd_fc = engine.pkts_fwd_fc.load(Ordering::Relaxed);
                        let reply_sym = engine.pkts_reply_sym.load(Ordering::Relaxed);
                        let reply_fc = engine.pkts_reply_fc.load(Ordering::Relaxed);
                        let d_fwd_sym = fwd_sym.saturating_sub(last_fwd_sym);
                        let d_fwd_fc = fwd_fc.saturating_sub(last_fwd_fc);
                        let d_reply_sym = reply_sym.saturating_sub(last_reply_sym);
                        let d_reply_fc = reply_fc.saturating_sub(last_reply_fc);

                        if d_fwd_sym + d_fwd_fc + d_reply_sym + d_reply_fc > 0
                            && tracing::enabled!(tracing::Level::DEBUG)
                        {
                            tracing::debug!(
                                window_s = 10,
                                fwd_sym_pps = d_fwd_sym / 10,
                                fwd_fc_pps = d_fwd_fc / 10,
                                reply_sym_pps = d_reply_sym / 10,
                                reply_fc_pps = d_reply_fc / 10,
                                alive_sym = engine.symmetric.len(),
                                alive_fc = engine.fullcone.len(),
                                "udp pps"
                            );
                        }
                        last_fwd_sym = fwd_sym;
                        last_fwd_fc = fwd_fc;
                        last_reply_sym = reply_sym;
                        last_reply_fc = reply_fc;
                    }
                }
            }
        });
    }

    for (idx, listener) in listeners.into_iter().enumerate() {
        let engine = Arc::clone(&engine);
        let shared = Arc::clone(&shared);
        let mut sd = shutdown_rx.clone();
        tokio::spawn(async move {
            recv_loop(idx, engine, listener, shared, &mut sd).await;
        });
    }

    Ok(engine)
}

async fn recv_loop(
    worker_idx: usize,
    engine: Arc<UdpEngine>,
    listener: Arc<TproxyUdp>,
    shared: Arc<SharedState>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut mbuf = MmsgBuf::new(MMSG_VLEN, MMSG_SLOT_CAP);

    let mut tx_buf: Vec<u8> = Vec::with_capacity(2048);
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { break; } }
            res = listener.recv_batch(&mut mbuf) => {
                match res {
                    Ok(0) => continue,
                    Ok(_n) => {

                        for (payload, peer, orig_dst) in mbuf.iter() {
                            if let Err(e) = dispatch_packet(&engine, &shared, peer, orig_dst, payload, &mut tx_buf).await {
                                tracing::debug!(worker_idx, %peer, %orig_dst, ?e, "udp dispatch failed");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(worker_idx, ?e, "udp recv error; backoff 100ms");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    tracing::info!(worker_idx, "udp worker exited");
}

async fn dispatch_packet(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
    tx_buf: &mut Vec<u8>,
) -> io::Result<()> {

    if !shared.proxy_allowed(peer.ip()) {
        tracing::debug!(%peer, %orig_dst, "udp peer not in proxy_cidr; drop");
        return Ok(());
    }

    if shared.route.load().block_quic && quic::is_quic_initial(payload) {
        tracing::debug!(%peer, %orig_dst, "quic blocked by route.block_quic");
        return Ok(());
    }

    if !shared.outbound.tun_ready_ok() {
        tracing::debug!(%peer, %orig_dst, "ovpn tun not ready; drop udp");
        return Ok(());
    }

    let kind = decide_flow_kind(engine, shared, peer, orig_dst, payload);
    match kind {
        FlowKind::Symmetric => {
            handle_symmetric(engine, shared, peer, orig_dst, payload, tx_buf).await
        }
        FlowKind::Fullcone => {
            handle_fullcone(engine, shared, peer, orig_dst, payload, tx_buf).await
        }
    }
}

fn decide_flow_kind(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
) -> FlowKind {
    if let Some(entry) = engine.flow_path.get(&(peer, orig_dst)) {
        entry.last_seen_ms.store(engine.now_ms(), Ordering::Relaxed);
        return entry.kind;
    }
    let is_fakeip = shared
        .fakeip
        .as_ref()
        .is_some_and(|f| f.contains(orig_dst.ip()));

    let kind = if is_fakeip || quic::is_quic_initial(payload) {
        FlowKind::Symmetric
    } else {
        FlowKind::Fullcone
    };
    engine.flow_path.insert(
        (peer, orig_dst),
        FlowEntry {
            kind,
            last_seen_ms: AtomicU64::new(engine.now_ms()),
        },
    );
    kind
}

async fn handle_symmetric(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
    tx_buf: &mut Vec<u8>,
) -> io::Result<()> {
    let key = (peer, orig_dst);

    let slot = engine.symmetric.get(&key).map(|e| e.value().clone());
    match slot {
        Some(SymSlot::Ready(session)) => {
            session
                .last_seen_ms
                .store(engine.now_ms(), Ordering::Relaxed);
            forward_symmetric(engine, shared, &session, peer, orig_dst, payload, tx_buf).await
        }
        Some(SymSlot::Pending(p)) => {
            p.push(payload.to_vec());
            Ok(())
        }
        None => match engine.symmetric.entry(key) {

            Entry::Occupied(e) => {
                let slot = e.get().clone();
                drop(e);
                match slot {
                    SymSlot::Ready(session) => {
                        session
                            .last_seen_ms
                            .store(engine.now_ms(), Ordering::Relaxed);
                        forward_symmetric(engine, shared, &session, peer, orig_dst, payload, tx_buf)
                            .await
                    }
                    SymSlot::Pending(p) => {
                        p.push(payload.to_vec());
                        Ok(())
                    }
                }
            }
            Entry::Vacant(v) => {
                let pending = Arc::new(Pending::new(payload.to_vec(), engine.now_ms()));
                v.insert(SymSlot::Pending(Arc::clone(&pending)));
                spawn_open_symmetric(engine, shared, peer, orig_dst, payload, pending);
                Ok(())
            }
        },
    }
}

fn spawn_open_symmetric(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    first_payload: &[u8],
    pending: Arc<Pending<Vec<u8>>>,
) {

    let (is_fakeip, fakeip_host) = resolve_fakeip(shared, orig_dst);

    let proto = if let Some(label) = crate::ip_rules::match_group(orig_dst.ip()) {
        StatProto::IpGroup(label)
    } else if is_udp_skip_port(orig_dst.port()) {
        StatProto::Skipped
    } else if quic::is_quic_initial(first_payload) {
        StatProto::Quic
    } else if fakeip_host.is_some() {
        StatProto::FakeIp
    } else {
        StatProto::RealIp
    };
    let engine = Arc::clone(engine);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {

        let opened = match shared.outbound.udp_upstream() {
            UdpUpstream::Socks5 { target, auth } => {
                open_symmetric_session(
                    &engine,
                    &shared,
                    target,
                    auth,
                    peer,
                    orig_dst,
                    engine.now_ms(),
                    is_fakeip,
                    fakeip_host,
                    proto,
                )
                .await
            }
            UdpUpstream::Direct {
                resolver,
                bind_device,
                so_mark,
            } => {
                open_direct_symmetric_session(
                    &engine,
                    &shared,
                    &resolver,
                    bind_device.as_deref(),
                    so_mark,
                    peer,
                    orig_dst,
                    engine.now_ms(),
                    is_fakeip,
                    fakeip_host,
                    proto,
                )
                .await
            }
        };
        let key = (peer, orig_dst);
        match opened {
            Ok(s) => {

                let installed = match engine.symmetric.entry(key) {
                    Entry::Occupied(mut e) => {
                        if matches!(e.get(), SymSlot::Pending(p) if Arc::ptr_eq(p, &pending)) {
                            e.insert(SymSlot::Ready(Arc::clone(&s)));
                            true
                        } else {
                            false
                        }
                    }
                    Entry::Vacant(_) => false,
                };
                if !installed {
                    tracing::debug!(%peer, %orig_dst, "symmetric slot superseded; drop fresh session");
                    shared.conn_table.close(s.rec.id);
                    return;
                }
                tracing::debug!(%peer, %orig_dst, alive = engine.len(), "udp symmetric session opened");
                if shared.route.load().log_sniffed {
                    tracing::info!(
                        "{}",
                        crate::logging::fmt_flow(
                            peer.ip(),
                            orig_dst,
                            None,
                            s.fakeip_host.as_deref(),
                            true
                        )
                    );
                }

                let pkts = pending.take();

                if matches!(s.rec.proto, StatProto::FakeIp | StatProto::RealIp)
                    && let Some(first) = pkts.first()
                {
                    s.rec.set_head(first);
                }
                let mut tx_buf: Vec<u8> = Vec::with_capacity(2048);
                for p in &pkts {
                    if let Err(e) =
                        forward_symmetric(&engine, &shared, &s, peer, orig_dst, p, &mut tx_buf)
                            .await
                    {
                        tracing::debug!(%peer, %orig_dst, ?e, "flush pending symmetric pkt failed");
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%peer, %orig_dst, ?e, "udp open_symmetric_session failed");
                pending.close();
                engine.symmetric.remove_if(
                    &key,
                    |_, v| matches!(v, SymSlot::Pending(p) if Arc::ptr_eq(p, &pending)),
                );

            }
        }
    });
}

async fn forward_symmetric(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    session: &SymmetricSession,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
    tx_buf: &mut Vec<u8>,
) -> io::Result<()> {

    if session.direct {
        session.relay_udp.send(payload).await?;
        session.rec.add_up(payload.len() as u64);
        engine.pkts_fwd_sym.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    if !session.sniff_done.load(Ordering::Relaxed) {
        let mut sniffer_guard = session.quic_sniffer.lock();
        if let Some(sn) = sniffer_guard.as_mut() {
            let _ = sn.feed(payload);
            if let Some(h) = sn.try_take_sni() {
                let ech = sn.ech_outer();
                if shared.route.load().log_sniffed {
                    tracing::info!(
                        "{}",
                        crate::logging::fmt_flow(peer.ip(), orig_dst, Some("quic"), Some(&h), true)
                    );
                }

                if session.is_fakeip || !ech {
                    session.routing_host.store(Some(Arc::new(h)));
                }
                *sniffer_guard = None;
                session.sniff_done.store(true, Ordering::Relaxed);
            } else if sn.is_done() {

                *sniffer_guard = None;
                session.sniff_done.store(true, Ordering::Relaxed);
            }
        } else {
            session.sniff_done.store(true, Ordering::Relaxed);
        }
    }

    match session.routing_host.load_full() {
        Some(host) => encode_udp_request_domain_into(tx_buf, &host, orig_dst.port(), payload)
            .map_err(io::Error::other)?,
        None if session.is_fakeip => {

            tracing::debug!(%peer, %orig_dst, "fakeip udp: no host (sni+lookback miss); drop");
            return Ok(());
        }
        None => encode_udp_request_into(tx_buf, orig_dst, payload),
    }
    session.relay_udp.send(tx_buf).await?;
    session.rec.add_up(payload.len() as u64);
    engine.pkts_fwd_sym.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn is_udp_skip_port(port: u16) -> bool {
    matches!(port, 53 | 67 | 68 | 123 | 161 | 162 | 514 | 1812 | 1813)
}

fn register_udp_record(
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    dst: SocketAddr,
    proto: StatProto,
    domain: Option<String>,
) -> Arc<ConnRecord> {
    let rec = Arc::new(
        ConnRecord::new(
            shared.id_gen.next_id(),
            (peer.ip(), peer.port()),
            (dst.ip(), dst.port()),
            proto,
            domain,
        )
        .with_inbound(InboundKind::TProxy, Transport::Udp),
    );
    shared.conn_table.insert(Arc::clone(&rec));
    rec
}

fn resolve_fakeip(shared: &Arc<SharedState>, orig_dst: SocketAddr) -> (bool, Option<String>) {
    match &shared.fakeip {
        Some(f) if f.contains(orig_dst.ip()) => {
            let host = match orig_dst.ip() {
                std::net::IpAddr::V4(v4) => f.lookback(v4).map(|h| h.to_string()),
                std::net::IpAddr::V6(_) => None,
            };
            (true, host)
        }
        _ => (false, None),
    }
}

async fn handle_fullcone(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    payload: &[u8],
    tx_buf: &mut Vec<u8>,
) -> io::Result<()> {
    let slot = engine.fullcone.get(&peer).map(|e| e.value().clone());
    match slot {
        Some(FcSlot::Ready(session)) => {
            session
                .last_seen_ms
                .store(engine.now_ms(), Ordering::Relaxed);
            forward_fullcone(engine, &session, orig_dst, payload, tx_buf).await
        }
        Some(FcSlot::Pending(p)) => {
            p.push((orig_dst, payload.to_vec()));
            Ok(())
        }
        None => match engine.fullcone.entry(peer) {
            Entry::Occupied(e) => {
                let slot = e.get().clone();
                drop(e);
                match slot {
                    FcSlot::Ready(session) => {
                        session
                            .last_seen_ms
                            .store(engine.now_ms(), Ordering::Relaxed);
                        forward_fullcone(engine, &session, orig_dst, payload, tx_buf).await
                    }
                    FcSlot::Pending(p) => {
                        p.push((orig_dst, payload.to_vec()));
                        Ok(())
                    }
                }
            }
            Entry::Vacant(v) => {
                let pending = Arc::new(Pending::new((orig_dst, payload.to_vec()), engine.now_ms()));
                v.insert(FcSlot::Pending(Arc::clone(&pending)));
                spawn_open_fullcone(engine, shared, peer, orig_dst, pending);
                Ok(())
            }
        },
    }
}

fn spawn_open_fullcone(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    peer: SocketAddr,
    orig_dst_hint: SocketAddr,
    pending: Arc<Pending<(SocketAddr, Vec<u8>)>>,
) {
    let engine = Arc::clone(engine);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {

        let opened = match shared.outbound.udp_upstream() {
            UdpUpstream::Socks5 { target, auth } => {
                open_fullcone_session(
                    &engine,
                    &shared,
                    target,
                    auth,
                    peer,
                    orig_dst_hint,
                    engine.now_ms(),
                )
                .await
            }
            UdpUpstream::Direct {
                bind_device,
                so_mark,
                ..
            } => {
                open_direct_fullcone_session(
                    &engine,
                    &shared,
                    bind_device.as_deref(),
                    so_mark,
                    peer,
                    orig_dst_hint,
                    engine.now_ms(),
                )
                .await
            }
        };
        match opened {
            Ok(s) => {
                let installed = match engine.fullcone.entry(peer) {
                    Entry::Occupied(mut e) => {
                        if matches!(e.get(), FcSlot::Pending(p) if Arc::ptr_eq(p, &pending)) {
                            e.insert(FcSlot::Ready(Arc::clone(&s)));
                            true
                        } else {
                            false
                        }
                    }
                    Entry::Vacant(_) => false,
                };
                if !installed {
                    tracing::debug!(%peer, "fullcone slot superseded; drop fresh session");
                    shared.conn_table.close(s.rec.id);
                    return;
                }
                tracing::debug!(%peer, %orig_dst_hint, alive = engine.len(), "udp fullcone session opened");
                if shared.route.load().log_sniffed {
                    tracing::info!(
                        "{}",
                        crate::logging::fmt_flow(peer.ip(), orig_dst_hint, None, None, true)
                    );
                }
                let pkts = pending.take();

                if let Some((_, first)) = pkts.first() {
                    s.rec.set_head(first);
                }
                let mut tx_buf: Vec<u8> = Vec::with_capacity(2048);
                for (dst, p) in &pkts {
                    if let Err(e) = forward_fullcone(&engine, &s, *dst, p, &mut tx_buf).await {
                        tracing::debug!(%peer, %dst, ?e, "flush pending fullcone pkt failed");
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%peer, %orig_dst_hint, ?e, "udp open_fullcone_session failed");
                pending.close();
                engine.fullcone.remove_if(
                    &peer,
                    |_, v| matches!(v, FcSlot::Pending(p) if Arc::ptr_eq(p, &pending)),
                );
            }
        }
    });
}

async fn forward_fullcone(
    engine: &Arc<UdpEngine>,
    session: &FullconeSession,
    orig_dst: SocketAddr,
    payload: &[u8],
    tx_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if session.direct {

        session.relay_udp.send_to(payload, orig_dst).await?;
    } else {
        encode_udp_request_into(tx_buf, orig_dst, payload);
        session.relay_udp.send(tx_buf).await?;
    }
    session.rec.add_up(payload.len() as u64);
    engine.pkts_fwd_fc.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

async fn relay_recv_batch(sock: &UdpSocket, rx: &mut MmsgRxBuf) -> io::Result<usize> {
    loop {
        sock.readable().await?;
        match sock.try_io(Interest::READABLE, || {
            recv_mmsg_payloads_nonblocking(sock.as_raw_fd(), rx)
        }) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn symmetric_spoof_src(
    canonical_ip: &mut Option<IpAddr>,
    src: SocketAddr,
    orig_dst: SocketAddr,
) -> Option<SocketAddr> {

    if src.ip().is_unspecified() {
        return None;
    }
    let canon = *canonical_ip.get_or_insert(src.ip());
    if src.ip() == canon {
        if src.port() == orig_dst.port() {
            None
        } else {
            Some(SocketAddr::new(orig_dst.ip(), src.port()))
        }
    } else {
        Some(src)
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_symmetric_session(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    socks_target: SocketAddr,
    auth: Option<Arc<(String, String)>>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    now_ms: u64,
    is_fakeip: bool,
    fakeip_host: Option<String>,
    proto: StatProto,
) -> io::Result<Arc<SymmetricSession>> {
    let (mut ctrl, relay_udp) = open_socks5_udp(socks_target, auth, orig_dst.is_ipv4()).await?;

    let spoof_udp = engine.spoof_cache.get_or_bind(orig_dst)?;
    let rec = register_udp_record(shared, peer, orig_dst, proto, fakeip_host.clone());
    let reader_relay = Arc::clone(&relay_udp);
    let engine_ref = Arc::clone(engine);
    let reader_rec = Arc::clone(&rec);
    let reader_shared = Arc::clone(shared);
    let reader = tokio::spawn(async move {
        let mut rx = MmsgRxBuf::new(MMSG_VLEN, REPLY_SLOT_CAP);
        let mut ctrl_buf = [0u8; 1];

        let spoof_fd = spoof_udp.as_raw_fd();

        let mut canonical_ip: Option<IpAddr> = None;
        loop {
            tokio::select! {
                res = relay_recv_batch(&reader_relay, &mut rx) => match res {
                    Ok(0) => continue,
                    Ok(_) => {

                        let mut out: [&[u8]; MMSG_VLEN] = [&b""[..]; MMSG_VLEN];
                        let mut k = 0usize;
                        for frame in rx.iter() {
                            match decode_udp_reply(frame) {
                                Ok((src, off)) => {
                                    reader_rec.add_down(frame[off..].len() as u64);
                                    match symmetric_spoof_src(&mut canonical_ip, src, orig_dst) {
                                        None => {
                                            out[k] = &frame[off..];
                                            k += 1;
                                        }
                                        Some(spoof_src) => {
                                            match engine_ref.spoof_cache.get_or_bind(spoof_src) {
                                                Ok(s) => match s.send_to(&frame[off..], peer).await {
                                                    Ok(_) => { engine_ref.pkts_reply_sym.fetch_add(1, Ordering::Relaxed); }

                                                    Err(e) => tracing::debug!(?e, %peer, %spoof_src, "alt-src spoof send failed; drop"),
                                                },
                                                Err(e) => tracing::debug!(?e, %src, "alt-src spoof bind failed; drop"),
                                            }
                                        }
                                    }
                                }
                                Err(e) => tracing::debug!(?e, "udp reply decode failed; drop"),
                            }
                        }
                        if k > 0 {
                            match send_mmsg_to(spoof_fd, &out[..k], peer) {
                                Ok(sent) => {
                                    engine_ref.pkts_reply_sym.fetch_add(sent as u64, Ordering::Relaxed);
                                    if sent < k {

                                        tracing::debug!(sent, batch = k, %peer, "spoof sendmmsg partial");
                                    }
                                }
                                Err(e) => tracing::debug!(?e, %peer, "spoof sendmmsg failed; drop batch"),
                            }
                        }
                    }
                    Err(e) => { tracing::debug!(?e, "relay recv ended; symmetric reader exits"); break; }
                },
                res = ctrl.read(&mut ctrl_buf) => match res {
                    Ok(0) => { tracing::debug!(%peer, %orig_dst, "socks5 ctrl FIN; teardown symmetric"); break; }
                    Err(e) => { tracing::debug!(?e, %peer, %orig_dst, "socks5 ctrl err; teardown symmetric"); break; }
                    Ok(_) => {   }
                }
            }
        }

        engine_ref.symmetric.remove(&(peer, orig_dst));
        engine_ref.flow_path.remove(&(peer, orig_dst));
        reader_shared.conn_table.close(reader_rec.id);
    });

    let sniff = !matches!(rec.proto, StatProto::IpGroup(_));
    Ok(Arc::new(SymmetricSession {
        relay_udp,
        reader,
        last_seen_ms: AtomicU64::new(now_ms),
        routing_host: ArcSwapOption::new(fakeip_host.clone().map(Arc::new)),
        sniff_done: AtomicBool::new(!sniff),
        quic_sniffer: Mutex::new(sniff.then(quic::IncrementalSniffer::new)),
        fakeip_host,
        is_fakeip,
        direct: false,
        rec,
    }))
}

async fn open_fullcone_session(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    socks_target: SocketAddr,
    auth: Option<Arc<(String, String)>>,
    peer: SocketAddr,
    orig_dst_hint: SocketAddr,
    now_ms: u64,
) -> io::Result<Arc<FullconeSession>> {
    let (mut ctrl, relay_udp) =
        open_socks5_udp(socks_target, auth, orig_dst_hint.is_ipv4()).await?;

    let rec = register_udp_record(shared, peer, orig_dst_hint, StatProto::RealIp, None);
    let reader_relay = Arc::clone(&relay_udp);
    let spoof_cache = Arc::clone(&engine.spoof_cache);
    let engine_ref = Arc::clone(engine);
    let reader_rec = Arc::clone(&rec);
    let reader_shared = Arc::clone(shared);
    let fallback_src = orig_dst_hint;
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        let mut ctrl_buf = [0u8; 1];
        loop {
            tokio::select! {
                res = reader_relay.recv(&mut buf) => match res {
                    Ok(n) => {
                        let frame = &buf[..n];
                        let (src, off) = match decode_udp_reply(frame) {
                            Ok(t) => t,
                            Err(e) => { tracing::debug!(?e, "udp reply decode failed; drop"); continue; }
                        };

                        reader_rec.add_down(frame[off..].len() as u64);
                        let spoof_src = if src.ip().is_unspecified() { fallback_src } else { src };
                        let spoof = match spoof_cache.get_or_bind(spoof_src) {
                            Ok(s) => s,
                            Err(e) => { tracing::debug!(?e, %src, "spoof bind failed; drop"); continue; }
                        };

                        match spoof.send_to(&frame[off..], peer).await {
                            Ok(_) => { engine_ref.pkts_reply_fc.fetch_add(1, Ordering::Relaxed); }
                            Err(e) => tracing::debug!(?e, %peer, "spoof send failed; drop reply"),
                        }
                    }
                    Err(e) => { tracing::debug!(?e, "relay recv ended; fullcone reader exits"); break; }
                },
                res = ctrl.read(&mut ctrl_buf) => match res {
                    Ok(0) => { tracing::debug!(%peer, "socks5 ctrl FIN; teardown fullcone"); break; }
                    Err(e) => { tracing::debug!(?e, %peer, "socks5 ctrl err; teardown fullcone"); break; }
                    Ok(_) => {   }
                }
            }
        }

        engine_ref.fullcone.remove(&peer);
        engine_ref
            .flow_path
            .retain(|(p, _), e| !(*p == peer && matches!(e.kind, FlowKind::Fullcone)));
        reader_shared.conn_table.close(reader_rec.id);
    });
    Ok(Arc::new(FullconeSession {
        relay_udp,
        reader,
        last_seen_ms: AtomicU64::new(now_ms),
        direct: false,
        rec,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn open_direct_symmetric_session(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    resolver: &Resolver,
    bind_device: Option<&str>,
    so_mark: Option<u32>,
    peer: SocketAddr,
    orig_dst: SocketAddr,
    now_ms: u64,
    is_fakeip: bool,
    fakeip_host: Option<String>,
    proto: StatProto,
) -> io::Result<Arc<SymmetricSession>> {

    let real_dst = match &fakeip_host {
        Some(host) => {
            let ip = resolver.resolve_v4(host).await?;
            SocketAddr::new(IpAddr::V4(ip), orig_dst.port())
        }
        None if !is_fakeip => orig_dst,
        None => {

            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "direct symmetric: fakeip without host",
            ));
        }
    };
    let relay =
        Arc::new(bind_direct_udp(real_dst.is_ipv4(), bind_device, so_mark, Some(real_dst)).await?);

    let spoof_udp = engine.spoof_cache.get_or_bind(orig_dst)?;
    let rec = register_udp_record(shared, peer, orig_dst, proto, fakeip_host.clone());
    let reader_relay = Arc::clone(&relay);
    let engine_ref = Arc::clone(engine);
    let reader_rec = Arc::clone(&rec);
    let reader_shared = Arc::clone(shared);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader_relay.recv(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {

                    match spoof_udp.send_to(&buf[..n], peer).await {
                        Ok(_) => {
                            reader_rec.add_down(n as u64);
                            engine_ref.pkts_reply_sym.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::debug!(?e, %peer, "direct symmetric spoof send failed; drop reply")
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(?e, "direct symmetric relay recv ended; reader exits");
                    break;
                }
            }
        }
        engine_ref.symmetric.remove(&(peer, orig_dst));
        engine_ref.flow_path.remove(&(peer, orig_dst));
        reader_shared.conn_table.close(reader_rec.id);
    });
    Ok(Arc::new(SymmetricSession {
        relay_udp: relay,
        reader,
        last_seen_ms: AtomicU64::new(now_ms),
        routing_host: ArcSwapOption::new(fakeip_host.clone().map(Arc::new)),
        sniff_done: AtomicBool::new(true),
        quic_sniffer: Mutex::new(None),
        fakeip_host,
        is_fakeip,
        direct: true,
        rec,
    }))
}

async fn open_direct_fullcone_session(
    engine: &Arc<UdpEngine>,
    shared: &Arc<SharedState>,
    bind_device: Option<&str>,
    so_mark: Option<u32>,
    peer: SocketAddr,
    orig_dst_hint: SocketAddr,
    now_ms: u64,
) -> io::Result<Arc<FullconeSession>> {
    let relay =
        Arc::new(bind_direct_udp(orig_dst_hint.is_ipv4(), bind_device, so_mark, None).await?);
    let rec = register_udp_record(shared, peer, orig_dst_hint, StatProto::RealIp, None);
    let reader_relay = Arc::clone(&relay);
    let spoof_cache = Arc::clone(&engine.spoof_cache);
    let engine_ref = Arc::clone(engine);
    let reader_rec = Arc::clone(&rec);
    let reader_shared = Arc::clone(shared);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader_relay.recv_from(&mut buf).await {
                Ok((n, real_src)) => {

                    let spoof = match spoof_cache.get_or_bind(real_src) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(?e, %real_src, "direct fullcone spoof bind failed; drop");
                            continue;
                        }
                    };

                    match spoof.send_to(&buf[..n], peer).await {
                        Ok(_) => {
                            reader_rec.add_down(n as u64);
                            engine_ref.pkts_reply_fc.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::debug!(?e, %peer, "direct fullcone spoof send failed; drop reply")
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(?e, "direct fullcone relay recv ended; reader exits");
                    break;
                }
            }
        }
        engine_ref.fullcone.remove(&peer);
        engine_ref
            .flow_path
            .retain(|(p, _), e| !(*p == peer && matches!(e.kind, FlowKind::Fullcone)));
        reader_shared.conn_table.close(reader_rec.id);
    });
    Ok(Arc::new(FullconeSession {
        relay_udp: relay,
        reader,
        last_seen_ms: AtomicU64::new(now_ms),
        direct: true,
        rec,
    }))
}

const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);

async fn open_socks5_udp(
    socks_target: SocketAddr,
    auth: Option<Arc<(String, String)>>,
    is_ipv4: bool,
) -> io::Result<(TcpStream, Arc<UdpSocket>)> {
    tokio::time::timeout(
        ASSOCIATE_TIMEOUT,
        open_socks5_udp_inner(socks_target, auth, is_ipv4),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5 udp associate timed out"))?
}

fn apply_ctrl_keepalive(fd: std::os::fd::RawFd) {
    let set = |level: libc::c_int, name: libc::c_int, val: libc::c_int| unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 30);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 4);
}

async fn open_socks5_udp_inner(
    socks_target: SocketAddr,
    auth: Option<Arc<(String, String)>>,
    is_ipv4: bool,
) -> io::Result<(TcpStream, Arc<UdpSocket>)> {
    let ctrl = TcpStream::connect(socks_target).await?;
    apply_ctrl_keepalive(ctrl.as_raw_fd());
    let mut ctrl = ctrl;
    let local_hint: SocketAddr = if is_ipv4 {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let bnd = udp_associate_auth(&mut ctrl, local_hint, auth.as_deref())
        .await
        .map_err(io::Error::other)?;
    let relay = if bnd.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    relay.connect(bnd).await?;
    Ok((ctrl, Arc::new(relay)))
}

async fn bind_direct_udp(
    is_ipv4: bool,
    bind_device: Option<&str>,
    so_mark: Option<u32>,
    connect_to: Option<SocketAddr>,
) -> io::Result<UdpSocket> {
    let std_sock = bind_udp_socket(is_ipv4, bind_device, so_mark).map_err(io::Error::other)?;
    let sock = UdpSocket::from_std(std_sock)?;
    if let Some(dst) = connect_to {
        sock.connect(dst).await?;
    }
    Ok(sock)
}

fn sweep_idle(engine: &Arc<UdpEngine>, shared: &Arc<SharedState>) -> (usize, usize, usize) {
    let now = engine.now_ms();
    let horizon = engine.idle_timeout.as_millis() as u64;

    let dead_sym: Vec<(SocketAddr, SocketAddr)> = engine
        .symmetric
        .iter()
        .filter(|e| {
            let last = match e.value() {
                SymSlot::Ready(s) => s.last_seen_ms.load(Ordering::Relaxed),
                SymSlot::Pending(p) => p.created_ms,
            };
            now.saturating_sub(last) > horizon
        })
        .map(|e| *e.key())
        .collect();
    for k in &dead_sym {

        if let Some((_, SymSlot::Ready(s))) = engine.symmetric.remove(k) {
            shared.conn_table.close(s.rec.id);
        }
        engine.flow_path.remove(k);
    }

    let dead_fc: Vec<SocketAddr> = engine
        .fullcone
        .iter()
        .filter(|e| {
            let last = match e.value() {
                FcSlot::Ready(s) => s.last_seen_ms.load(Ordering::Relaxed),
                FcSlot::Pending(p) => p.created_ms,
            };
            now.saturating_sub(last) > horizon
        })
        .map(|e| *e.key())
        .collect();
    for k in &dead_fc {
        if let Some((_, FcSlot::Ready(s))) = engine.fullcone.remove(k) {
            shared.conn_table.close(s.rec.id);
        }
    }

    let dead_fp: Vec<(SocketAddr, SocketAddr)> = engine
        .flow_path
        .iter()
        .filter(|e| now.saturating_sub(e.value().last_seen_ms.load(Ordering::Relaxed)) > horizon)
        .map(|e| *e.key())
        .collect();
    for k in &dead_fp {

        engine.flow_path.remove_if(k, |_, v| {
            now.saturating_sub(v.last_seen_ms.load(Ordering::Relaxed)) > horizon
        });
    }

    (dead_sym.len(), dead_fc.len(), dead_fp.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteCfg, SocksCfg};

    #[test]
    fn decide_flow_kind_unknown_payload_is_fullcone() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let engine = make_test_engine();
            let shared = make_test_shared(None);
            let peer: SocketAddr = "10.0.0.1:1111".parse().unwrap();
            let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();

            let dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
            let k = decide_flow_kind(&engine, &shared, peer, dst, dns);
            assert!(matches!(k, FlowKind::Fullcone));

            let k2 = decide_flow_kind(&engine, &shared, peer, dst, dns);
            assert!(matches!(k2, FlowKind::Fullcone));
        });
    }

    #[test]
    fn decide_flow_kind_fakeip_dst_forced_symmetric() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let engine = make_test_engine();
            let shared = make_test_shared(Some("7.0.0.0/8"));
            let peer: SocketAddr = "10.0.0.1:2000".parse().unwrap();

            let dst: SocketAddr = "7.1.2.3:443".parse().unwrap();
            let not_quic = b"\x00\x01\x02\x03 not a quic initial";
            assert!(matches!(
                decide_flow_kind(&engine, &shared, peer, dst, not_quic),
                FlowKind::Symmetric
            ));

            let real: SocketAddr = "1.1.1.1:443".parse().unwrap();
            assert!(matches!(
                decide_flow_kind(&engine, &shared, peer, real, not_quic),
                FlowKind::Fullcone
            ));
        });
    }

    #[tokio::test]
    async fn sweep_removes_both_kinds() {
        let engine = make_test_engine();

        let peer: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();

        let relay_sym = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reader_sym = tokio::spawn(async { std::future::pending::<()>().await });
        let sym = Arc::new(SymmetricSession {
            relay_udp: relay_sym,
            reader: reader_sym,
            last_seen_ms: AtomicU64::new(engine.now_ms()),
            routing_host: ArcSwapOption::new(None),
            sniff_done: AtomicBool::new(true),
            quic_sniffer: Mutex::new(None),
            fakeip_host: None,
            is_fakeip: false,
            direct: false,
            rec: dummy_rec(),
        });
        engine.symmetric.insert((peer, dst), SymSlot::Ready(sym));
        engine.flow_path.insert(
            (peer, dst),
            FlowEntry {
                kind: FlowKind::Symmetric,
                last_seen_ms: AtomicU64::new(engine.now_ms()),
            },
        );

        let relay_fc = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reader_fc = tokio::spawn(async { std::future::pending::<()>().await });
        let fc = Arc::new(FullconeSession {
            relay_udp: relay_fc,
            reader: reader_fc,
            last_seen_ms: AtomicU64::new(engine.now_ms()),
            direct: false,
            rec: dummy_rec(),
        });
        engine.fullcone.insert(peer, FcSlot::Ready(fc));
        engine.flow_path.insert(
            (peer, "9.9.9.9:53".parse().unwrap()),
            FlowEntry {
                kind: FlowKind::Fullcone,
                last_seen_ms: AtomicU64::new(engine.now_ms()),
            },
        );

        assert_eq!(engine.symmetric.len(), 1);
        assert_eq!(engine.fullcone.len(), 1);
        assert_eq!(engine.flow_path.len(), 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let shared = make_test_shared(None);
        let (s, f, _) = sweep_idle(&engine, &shared);
        assert_eq!(s, 1);
        assert_eq!(f, 1);
        assert_eq!(engine.symmetric.len(), 0);
        assert_eq!(engine.fullcone.len(), 0);
        assert_eq!(engine.flow_path.len(), 0);
    }

    #[tokio::test]
    async fn sweep_reclaims_orphan_flow_path() {
        let engine = make_test_engine();
        let peer: SocketAddr = "10.0.0.3:3333".parse().unwrap();

        engine.flow_path.insert(
            (peer, "1.1.1.1:443".parse().unwrap()),
            FlowEntry {
                kind: FlowKind::Symmetric,
                last_seen_ms: AtomicU64::new(engine.now_ms()),
            },
        );
        engine.flow_path.insert(
            (peer, "8.8.8.8:53".parse().unwrap()),
            FlowEntry {
                kind: FlowKind::Fullcone,
                last_seen_ms: AtomicU64::new(engine.now_ms()),
            },
        );
        assert_eq!(engine.flow_path.len(), 2);
        assert_eq!(engine.symmetric.len(), 0);
        assert_eq!(engine.fullcone.len(), 0);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let shared = make_test_shared(None);
        let (_, _, fp_removed) = sweep_idle(&engine, &shared);
        assert_eq!(fp_removed, 2, "orphan flow_path should be reclaimed");
        assert_eq!(engine.flow_path.len(), 0);
    }

    #[tokio::test]
    async fn sweep_reclaims_stale_pending_slots() {
        let engine = make_test_engine();
        let peer: SocketAddr = "10.0.0.7:7777".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        engine.symmetric.insert(
            (peer, dst),
            SymSlot::Pending(Arc::new(Pending::new(vec![1u8], engine.now_ms()))),
        );
        engine.fullcone.insert(
            peer,
            FcSlot::Pending(Arc::new(Pending::new((dst, vec![2u8]), engine.now_ms()))),
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        let shared = make_test_shared(None);
        sweep_idle(&engine, &shared);
        assert!(engine.symmetric.is_empty() && engine.fullcone.is_empty());
    }

    #[tokio::test]
    async fn pending_slot_removed_on_open_failure() {
        let engine = make_test_engine();
        let shared = make_test_shared_with(None, closed_port_addr());
        let peer: SocketAddr = "10.0.0.8:8888".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut tx = Vec::new();
        dispatch_packet(&engine, &shared, peer, dst, &quic_initial_pkt(), &mut tx)
            .await
            .unwrap();
        for _ in 0..200 {
            if engine.symmetric.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            engine.symmetric.is_empty(),
            "failed open must clear pending slot"
        );
    }

    #[tokio::test]
    async fn pending_packets_flush_after_session_opens() {
        use crate::config::{Config, OutboundCfg, OutboundMode};
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = upstream.local_addr().unwrap();

        let engine = make_test_engine();
        let cfg = Config {
            outbound: OutboundCfg {
                mode: OutboundMode::Free,
                ..Default::default()
            },
            ..Default::default()
        };
        let shared = Arc::new(SharedState::new(&cfg));
        let peer: SocketAddr = "10.0.0.9:9999".parse().unwrap();

        let pkt_a = b"\x00\x01stun-ish-payload-A".to_vec();
        let pkt_b = b"\x00\x01stun-ish-payload-B".to_vec();
        let mut tx = Vec::new();
        dispatch_packet(&engine, &shared, peer, dst, &pkt_a, &mut tx)
            .await
            .unwrap();
        dispatch_packet(&engine, &shared, peer, dst, &pkt_b, &mut tx)
            .await
            .unwrap();

        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 2048];
        while got.len() < 2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), upstream.recv_from(&mut buf))
                .await
                .expect("pending packets must be flushed after session opens")
                .unwrap();
            got.push(buf[..n].to_vec());
        }
        assert!(
            got.contains(&pkt_a) && got.contains(&pkt_b),
            "both queued packets delivered"
        );
        assert!(
            matches!(
                engine.fullcone.get(&peer).map(|e| e.value().clone()),
                Some(FcSlot::Ready(_))
            ),
            "slot must be Ready after open"
        );
    }

    #[tokio::test]
    async fn pending_packets_flush_socks5_symmetric() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        if sb_tproxy::udp::bind_spoof_udp("127.0.0.1:0".parse().unwrap()).is_err() {
            eprintln!("skip: IP_TRANSPARENT needs CAP_NET_ADMIN");
            return;
        }
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bnd = relay.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = tcp.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    if s.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut req = [0u8; 10];
                    if s.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let mut rep = vec![0x05, 0x00, 0x00, 0x01];
                    match bnd.ip() {
                        std::net::IpAddr::V4(v4) => rep.extend_from_slice(&v4.octets()),
                        std::net::IpAddr::V6(_) => return,
                    }
                    rep.extend_from_slice(&bnd.port().to_be_bytes());
                    let _ = s.write_all(&rep).await;
                    let mut hold = [0u8; 1];
                    let _ = s.read_exact(&mut hold).await;
                });
            }
        });

        let engine = make_test_engine();
        let shared = make_test_shared_with(None, socks_addr);
        let peer: SocketAddr = "10.0.0.9:9999".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let pkt = quic_initial_pkt();
        let mut tx = Vec::new();

        dispatch_packet(&engine, &shared, peer, dst, &pkt, &mut tx)
            .await
            .unwrap();
        dispatch_packet(&engine, &shared, peer, dst, &pkt, &mut tx)
            .await
            .unwrap();

        let mut got = 0;
        let mut buf = [0u8; 2048];
        while got < 2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), relay.recv_from(&mut buf))
                .await
                .expect("pending packets must be flushed after session opens")
                .unwrap();
            let (src, off) = decode_udp_reply(&buf[..n]).unwrap();
            assert_eq!(src, dst, "no SNI/fakeip → IP-style encapsulation should carry original destination");
            assert_eq!(&buf[off..n], &pkt[..]);
            got += 1;
        }
        assert!(
            matches!(
                engine
                    .symmetric
                    .get(&(peer, dst))
                    .map(|e| e.value().clone()),
                Some(SymSlot::Ready(_))
            ),
            "slot must be Ready after open"
        );
    }

    #[tokio::test]
    async fn bind_direct_udp_connected_and_unconnected() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let paddr = peer.local_addr().unwrap();

        let connected = bind_direct_udp(true, None, None, Some(paddr))
            .await
            .unwrap();
        connected.send(b"x").await.unwrap();
        let mut b = [0u8; 8];
        let (n, _) = peer.recv_from(&mut b).await.unwrap();
        assert_eq!(n, 1);

        let unconn = bind_direct_udp(true, None, None, None).await.unwrap();
        unconn.send_to(b"yy", paddr).await.unwrap();
        let (n2, _) = peer.recv_from(&mut b).await.unwrap();
        assert_eq!(n2, 2);
    }

    #[tokio::test]
    async fn block_quic_drops_quic_initial_before_classify() {
        let engine = make_test_engine();
        let shared = make_test_shared(None);
        shared.route.store(&RouteCfg {
            block_quic: true,
            ..RouteCfg::default()
        });
        let peer: SocketAddr = "10.0.0.4:4444".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut tx = Vec::new();
        let res = dispatch_packet(&engine, &shared, peer, dst, &quic_initial_pkt(), &mut tx).await;
        assert!(res.is_ok());
        assert!(engine.flow_path.is_empty(), "blocked QUIC should not enter diversion");
        assert!(engine.symmetric.is_empty() && engine.fullcone.is_empty());
    }

    #[tokio::test]
    async fn block_quic_passes_non_quic_udp_to_classify() {
        let engine = make_test_engine();
        let shared = make_test_shared_with(None, closed_port_addr());
        shared.route.store(&RouteCfg {
            block_quic: true,
            ..RouteCfg::default()
        });
        let peer: SocketAddr = "10.0.0.5:5555".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:3478".parse().unwrap();

        let stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42stun-txid....";
        let mut tx = Vec::new();
        let _ = dispatch_packet(&engine, &shared, peer, dst, stun, &mut tx).await;
        let entry = engine
            .flow_path
            .get(&(peer, dst))
            .expect("non-QUIC UDP should enter diversion");
        assert!(matches!(entry.kind, FlowKind::Fullcone));
    }

    #[test]
    fn symmetric_spoof_src_restore_semantics() {
        let orig_dst: SocketAddr = "7.63.8.106:3478".parse().unwrap();
        let primary: SocketAddr = "77.72.169.213:3478".parse().unwrap();
        let mut canon = None;

        assert_eq!(symmetric_spoof_src(&mut canon, primary, orig_dst), None);
        assert_eq!(canon, Some(primary.ip()));

        assert_eq!(symmetric_spoof_src(&mut canon, primary, orig_dst), None);

        let alt_port: SocketAddr = "77.72.169.213:3479".parse().unwrap();
        assert_eq!(
            symmetric_spoof_src(&mut canon, alt_port, orig_dst),
            Some("7.63.8.106:3479".parse().unwrap())
        );

        let changed: SocketAddr = "77.72.169.210:3479".parse().unwrap();
        assert_eq!(
            symmetric_spoof_src(&mut canon, changed, orig_dst),
            Some(changed)
        );

        assert_eq!(canon, Some(primary.ip()));
        assert_eq!(symmetric_spoof_src(&mut canon, primary, orig_dst), None);
    }

    #[test]
    fn symmetric_spoof_src_unspecified_placeholder() {
        let orig_dst: SocketAddr = "7.1.2.3:443".parse().unwrap();
        let mut canon = None;
        let placeholder: SocketAddr = "0.0.0.0:443".parse().unwrap();
        assert_eq!(symmetric_spoof_src(&mut canon, placeholder, orig_dst), None);
        assert_eq!(canon, None, "placeholder source should not be learned");

        let real: SocketAddr = "1.2.3.4:443".parse().unwrap();
        assert_eq!(symmetric_spoof_src(&mut canon, real, orig_dst), None);
        assert_eq!(canon, Some(real.ip()));
    }

    #[tokio::test]
    async fn quic_initial_classified_symmetric_when_block_off() {
        let engine = make_test_engine();
        let shared = make_test_shared_with(None, closed_port_addr());
        let peer: SocketAddr = "10.0.0.6:6666".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut tx = Vec::new();
        let _ = dispatch_packet(&engine, &shared, peer, dst, &quic_initial_pkt(), &mut tx).await;
        let entry = engine
            .flow_path
            .get(&(peer, dst))
            .expect("when block_quic=false, QUIC should enter diversion");
        assert!(matches!(entry.kind, FlowKind::Symmetric));
    }

    fn make_test_engine() -> Arc<UdpEngine> {
        Arc::new(UdpEngine {
            symmetric: Arc::new(DashMap::new()),
            fullcone: Arc::new(DashMap::new()),
            flow_path: Arc::new(DashMap::new()),
            spoof_cache: Arc::new(SpoofCache::new(64)),
            started: Instant::now(),
            idle_timeout: Duration::from_millis(5),
            pkts_fwd_sym: AtomicU64::new(0),
            pkts_fwd_fc: AtomicU64::new(0),
            pkts_reply_sym: AtomicU64::new(0),
            pkts_reply_fc: AtomicU64::new(0),
        })
    }

    fn make_test_shared(fake_cidr: Option<&str>) -> Arc<SharedState> {
        make_test_shared_with(fake_cidr, SocksCfg::default().server)
    }

    fn make_test_shared_with(fake_cidr: Option<&str>, socks: SocketAddr) -> Arc<SharedState> {
        use crate::config::*;
        let dns = fake_cidr.map(|c| DnsCfg {
            enabled: true,
            listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: c.parse().unwrap(),
            ttl: 3,
            max_entries: Some(1024),
            max_mem_pct: 30,
            shards: 16,
        });
        let cfg = Config {
            log: LogCfg::default(),
            inbound: InboundCfg::default(),
            socks5: SocksCfg {
                server: socks,
                ..SocksCfg::default()
            },
            route: RouteCfg::default(),
            stats: None,
            dns,

            outbound: OutboundCfg {
                mode: OutboundMode::Yaml,
                ..Default::default()
            },
            ..Default::default()
        };
        Arc::new(SharedState::new(&cfg))
    }

    fn dummy_rec() -> Arc<ConnRecord> {
        Arc::new(
            ConnRecord::new(
                sb_stats::ConnId(0),
                ("10.0.0.1".parse().unwrap(), 1),
                ("1.2.3.4".parse().unwrap(), 443),
                StatProto::Unknown,
                None,
            )
            .with_inbound(InboundKind::TProxy, Transport::Udp),
        )
    }

    fn closed_port_addr() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }

    fn quic_initial_pkt() -> Vec<u8> {
        let mut pkt = vec![0xC0u8, 0, 0, 0, 1, 0, 0, 0, 0x04];
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        pkt
    }
}
