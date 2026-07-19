// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::error::OutboundErr;
use crate::socks5;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy)]
pub struct PoolCfg {
    pub min: usize,
    pub max: usize,
    pub idle_timeout: Duration,
}

impl Default for PoolCfg {
    fn default() -> Self {
        Self {
            min: 8,
            max: 128,
            idle_timeout: Duration::from_secs(300),
        }
    }
}

struct IdleConn {
    stream: TcpStream,
    put_at: Instant,
}

#[derive(Default)]
struct Pressure {
    cold_acquires: AtomicU64,
    discarded_dead: AtomicU64,
    new_warmed: AtomicU64,
}

struct Inner {
    target: SocketAddr,

    auth: Option<Arc<(String, String)>>,
    cfg: ArcSwap<PoolCfg>,
    idle: Mutex<VecDeque<IdleConn>>,
    pressure: Pressure,

    warm_notify: Notify,
}

#[derive(Clone)]
pub struct SocksPool {
    inner: Arc<Inner>,
}

impl SocksPool {

    pub fn new(target: SocketAddr, cfg: PoolCfg) -> Self {
        Self::with_auth(target, cfg, None)
    }

    pub fn with_auth(
        target: SocketAddr,
        cfg: PoolCfg,
        auth: Option<Arc<(String, String)>>,
    ) -> Self {
        let initial_cap = cfg.min.max(16);
        Self {
            inner: Arc::new(Inner {
                target,
                auth,
                cfg: ArcSwap::new(Arc::new(cfg)),
                idle: Mutex::new(VecDeque::with_capacity(initial_cap)),
                pressure: Pressure::default(),
                warm_notify: Notify::new(),
            }),
        }
    }

    pub fn target(&self) -> SocketAddr {
        self.inner.target
    }

    pub fn auth(&self) -> Option<Arc<(String, String)>> {
        self.inner.auth.clone()
    }

    pub fn idle_len(&self) -> usize {
        self.inner.idle.lock().len()
    }

    pub fn cfg(&self) -> PoolCfg {
        **self.inner.cfg.load()
    }

    pub fn cold_acquires(&self) -> u64 {
        self.inner.pressure.cold_acquires.load(Ordering::Relaxed)
    }

    pub fn discarded_dead(&self) -> u64 {
        self.inner.pressure.discarded_dead.load(Ordering::Relaxed)
    }

    pub fn warmed(&self) -> u64 {
        self.inner.pressure.new_warmed.load(Ordering::Relaxed)
    }

    pub fn resize(&self, new_cfg: PoolCfg) {
        let old = self.cfg();
        self.inner.cfg.store(Arc::new(new_cfg));

        self.inner.warm_notify.notify_one();
        tracing::info!(
            ?old, new = ?new_cfg, idle_now = self.idle_len(),
            "socks pool resized"
        );
    }

    pub async fn acquire(&self) -> Result<TcpStream, OutboundErr> {
        let now = Instant::now();
        let cfg = self.cfg();
        let mut dead = 0u64;
        let mut dropped_stale = false;
        let chosen: Option<TcpStream> = loop {
            let cand = {
                let mut g = self.inner.idle.lock();

                while let Some(front) = g.front() {
                    if now.duration_since(front.put_at) >= cfg.idle_timeout {
                        g.pop_front();
                        dropped_stale = true;
                    } else {
                        break;
                    }
                }
                g.pop_front()
            };
            match cand {
                None => break None,
                Some(ic) => {
                    if is_stream_alive(&ic.stream) {
                        break Some(ic.stream);
                    }
                    dead += 1;
                }
            }
        };
        if dead > 0 {
            self.inner
                .pressure
                .discarded_dead
                .fetch_add(dead, Ordering::Relaxed);
        }
        if dead > 0 || dropped_stale {
            self.inner.warm_notify.notify_one();
        }
        if let Some(s) = chosen {
            return Ok(s);
        }

        self.inner
            .pressure
            .cold_acquires
            .fetch_add(1, Ordering::Relaxed);
        self.inner.warm_notify.notify_one();
        let s = dial_and_handshake(self.inner.target, self.inner.auth.as_deref()).await?;
        Ok(s)
    }

    pub fn release_clean(&self, stream: TcpStream) {
        let cfg = self.cfg();
        let mut g = self.inner.idle.lock();
        if g.len() >= cfg.max {

            return;
        }
        g.push_back(IdleConn {
            stream,
            put_at: Instant::now(),
        });
    }

    pub async fn connect(
        &self,
        dst: SocketAddr,
        host: Option<&str>,
    ) -> Result<TcpStream, OutboundErr> {
        let mut s = self.acquire().await?;
        socks5::send_connect(&mut s, dst, host).await?;
        Ok(s)
    }

    pub fn spawn_warmer(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.warmer_loop().await;
        })
    }

    async fn warmer_loop(self: Arc<Self>) {

        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = self.inner.warm_notify.notified() => {}
            }
            self.warm_once().await;
        }
    }

    async fn warm_once(&self) {

        self.evict_stale();
        let cfg = self.cfg();
        let cur_idle = self.idle_len();
        if cur_idle >= cfg.min {
            return;
        }

        let pressure_boost = self
            .inner
            .pressure
            .cold_acquires
            .swap(0, Ordering::Relaxed)
            .min(cfg.max as u64) as usize;
        let target = (cfg.min + pressure_boost).min(cfg.max);
        let need = target.saturating_sub(cur_idle);

        let batch = need.min(cfg.min.max(4));

        let mut consecutive_fail = 0usize;
        const MAX_CONSECUTIVE_FAIL: usize = 3;
        for _ in 0..batch {
            match dial_and_handshake(self.inner.target, self.inner.auth.as_deref()).await {
                Ok(s) => {
                    consecutive_fail = 0;
                    self.inner
                        .pressure
                        .new_warmed
                        .fetch_add(1, Ordering::Relaxed);
                    let cfg = self.cfg();
                    let mut g = self.inner.idle.lock();
                    if g.len() < cfg.max {
                        g.push_back(IdleConn {
                            stream: s,
                            put_at: Instant::now(),
                        });
                    } else {
                        drop(g);

                    }
                }
                Err(e) => {
                    consecutive_fail += 1;
                    tracing::debug!(?e, consecutive_fail, target = %self.inner.target, "warmer dial failed");
                    if consecutive_fail >= MAX_CONSECUTIVE_FAIL {
                        break;
                    }
                }
            }
        }
    }

    fn evict_stale(&self) {
        let cfg = self.cfg();
        let now = Instant::now();
        let mut g = self.inner.idle.lock();

        while let Some(front) = g.front() {
            if now.duration_since(front.put_at) >= cfg.idle_timeout {
                g.pop_front();
            } else {
                break;
            }
        }
    }
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

async fn dial_and_handshake(
    target: SocketAddr,
    auth: Option<&(String, String)>,
) -> Result<TcpStream, OutboundErr> {
    match tokio::time::timeout(DIAL_TIMEOUT, dial_and_handshake_inner(target, auth)).await {
        Ok(res) => res,
        Err(_) => Err(OutboundErr::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "socks5 dial/handshake timed out",
        ))),
    }
}

async fn dial_and_handshake_inner(
    target: SocketAddr,
    auth: Option<&(String, String)>,
) -> Result<TcpStream, OutboundErr> {
    let mut s = TcpStream::connect(target).await?;

    s.set_nodelay(true).ok();

    apply_tcp_keepalive(&s,   30,   10,   4);
    socks5::handshake(&mut s, auth).await?;
    Ok(s)
}

fn apply_tcp_keepalive(s: &TcpStream, idle_s: i32, intvl_s: i32, cnt: i32) {
    let fd = s.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {

        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle_s as *const _ as *const libc::c_void,
            std::mem::size_of_val(&idle_s) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &intvl_s as *const _ as *const libc::c_void,
            std::mem::size_of_val(&intvl_s) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &cnt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&cnt) as libc::socklen_t,
        );
    }
}

fn is_stream_alive(s: &TcpStream) -> bool {
    let mut probe = [0u8; 1];
    match s.try_read(&mut probe) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
        Ok(0) => false,
        Ok(_) => false,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn default_cfg_sane() {
        let c = PoolCfg::default();
        assert!(c.min <= c.max);
        assert!(c.idle_timeout.as_secs() >= 30);
    }

    #[tokio::test]
    async fn empty_pool_starts_empty() {
        let p = SocksPool::new("127.0.0.1:1080".parse().unwrap(), PoolCfg::default());
        assert_eq!(p.idle_len(), 0);
        assert_eq!(p.target(), "127.0.0.1:1080".parse().unwrap());
    }

    #[test]
    fn resize_updates_cfg() {
        let p = SocksPool::new("127.0.0.1:1080".parse().unwrap(), PoolCfg::default());
        assert_eq!(p.cfg().max, 128);
        p.resize(PoolCfg {
            min: 16,
            max: 256,
            idle_timeout: Duration::from_secs(600),
        });
        assert_eq!(p.cfg().min, 16);
        assert_eq!(p.cfg().max, 256);
        assert_eq!(p.cfg().idle_timeout, Duration::from_secs(600));
    }

    fn spawn_fake_socks_with_killer(
        listener: TcpListener,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let (kill_tx, kill_rx) = tokio::sync::watch::channel(false);
        let h = tokio::spawn(async move {
            let kill_rx = kill_rx.clone();
            loop {
                let mut k = kill_rx.clone();
                let accept = listener.accept();
                tokio::pin!(accept);
                let (mut sock, _) = tokio::select! {
                    r = &mut accept => match r {
                        Ok(x) => x,
                        Err(_) => return,
                    },
                    _ = k.changed() => return,
                };
                let mut k2 = kill_rx.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut hdr = [0u8; 3];
                    let read_hdr = sock.read_exact(&mut hdr);
                    tokio::pin!(read_hdr);
                    tokio::select! {
                        r = &mut read_hdr => {
                            if r.is_err() { return; }
                        }
                        _ = k2.changed() => return,
                    }
                    let _ = sock.write_all(&[0x05, 0x00]).await;

                    tokio::select! {
                        _ = k2.changed() => {
                            let _ = sock.shutdown().await;
                        }
                        _ = async {
                            let mut buf = [0u8; 1];
                            let _ = sock.read_exact(&mut buf).await;
                        } => {}
                    }
                });
            }
        });
        (h, kill_tx)
    }

    async fn spawn_fake_socks(
        addr: SocketAddr,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let listener = TcpListener::bind(addr).await.unwrap();
        spawn_fake_socks_with_killer(listener)
    }

    async fn pick_port() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    #[tokio::test]
    async fn warmer_fills_to_min() {
        let addr = pick_port().await;
        let (_srv, _kill) = spawn_fake_socks(addr).await;

        let pool = Arc::new(SocksPool::new(
            addr,
            PoolCfg {
                min: 3,
                max: 8,
                idle_timeout: Duration::from_secs(60),
            },
        ));
        let _h = pool.spawn_warmer();

        for _ in 0..50 {
            if pool.idle_len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            pool.idle_len() >= 3,
            "expected idle≥3, got {}",
            pool.idle_len()
        );
        assert!(pool.warmed() >= 3);
    }

    #[tokio::test]
    async fn warmer_fills_with_userpass_auth() {

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut head = [0u8; 2];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; head[1] as usize];
                    let _ = s.read_exact(&mut methods).await;

                    let _ = s.write_all(&[0x05, 0x02]).await;
                    let mut h = [0u8; 2];
                    if s.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let mut user = vec![0u8; h[1] as usize];
                    let _ = s.read_exact(&mut user).await;
                    let mut pl = [0u8; 1];
                    let _ = s.read_exact(&mut pl).await;
                    let mut pass = vec![0u8; pl[0] as usize];
                    let _ = s.read_exact(&mut pass).await;
                    let ok = user == b"alice" && pass == b"secret";
                    let _ = s.write_all(&[0x01, if ok { 0 } else { 1 }]).await;

                    let mut b = [0u8; 1];
                    let _ = s.read_exact(&mut b).await;
                });
            }
        });

        let pool = Arc::new(SocksPool::with_auth(
            addr,
            PoolCfg {
                min: 2,
                max: 4,
                idle_timeout: Duration::from_secs(60),
            },
            Some(Arc::new(("alice".into(), "secret".into()))),
        ));
        assert_eq!(
            pool.auth().as_deref(),
            Some(&("alice".into(), "secret".into()))
        );
        let _h = pool.spawn_warmer();
        for _ in 0..50 {
            if pool.idle_len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            pool.idle_len() >= 2,
            "warmer should fill with auth, got {}",
            pool.idle_len()
        );
    }

    #[tokio::test]
    async fn acquire_uses_idle_first() {
        let addr = pick_port().await;
        let (_srv, _kill) = spawn_fake_socks(addr).await;

        let pool = Arc::new(SocksPool::new(
            addr,
            PoolCfg {
                min: 2,
                max: 4,
                idle_timeout: Duration::from_secs(60),
            },
        ));
        let _h = pool.spawn_warmer();

        for _ in 0..50 {
            if pool.idle_len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(pool.idle_len() >= 2);
        let cold0 = pool.cold_acquires();
        let _conn = pool.acquire().await.unwrap();

        assert_eq!(pool.cold_acquires(), cold0);
    }

    #[tokio::test]
    async fn acquire_drops_dead_then_dials_cold() {
        let addr = pick_port().await;
        let (_srv, kill) = spawn_fake_socks(addr).await;

        let pool = Arc::new(SocksPool::new(
            addr,
            PoolCfg {
                min: 1,
                max: 4,
                idle_timeout: Duration::from_secs(60),
            },
        ));
        let _h = pool.spawn_warmer();

        for _ in 0..50 {
            if pool.idle_len() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(pool.idle_len() >= 1);

        let _ = kill.send(true);

        tokio::time::sleep(Duration::from_millis(120)).await;

        let dead0 = pool.discarded_dead();

        let r = pool.acquire().await;

        assert!(pool.discarded_dead() > dead0);

        let _ = r;
    }

    #[tokio::test]
    async fn evict_stale_removes_old_idle() {
        let addr = pick_port().await;
        let (_srv, _kill) = spawn_fake_socks(addr).await;
        let pool = Arc::new(SocksPool::new(
            addr,
            PoolCfg {
                min: 2,
                max: 4,
                idle_timeout: Duration::from_millis(120),
            },
        ));
        let _h = pool.spawn_warmer();
        for _ in 0..50 {
            if pool.idle_len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let before = pool.idle_len();
        assert!(before >= 2);

        tokio::time::sleep(Duration::from_millis(160)).await;
        pool.evict_stale();

        assert_eq!(pool.idle_len(), 0);
    }

    #[tokio::test]
    async fn is_alive_detects_eof_after_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();

            let _ = s.shutdown().await;
        });
        let s = TcpStream::connect(addr).await.unwrap();
        srv.await.unwrap();

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!is_stream_alive(&s));
    }

    #[tokio::test]
    async fn is_alive_true_when_no_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();

            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(s);
        });
        let s = TcpStream::connect(addr).await.unwrap();

        assert!(is_stream_alive(&s));
        drop(s);
        srv.await.unwrap();
    }
}
