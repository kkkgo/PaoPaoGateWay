// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

use crate::config::{Config, OutboundMode};
use crate::resolver::Resolver;
use sb_outbound::direct::{connect_tcp_direct, device_exists};
use sb_outbound::{PoolCfg, SocksPool};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;

const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DirectOutbound {
    pub resolver: Arc<Resolver>,

    pub bind_device: Option<String>,

    pub so_mark: Option<u32>,

    pub tun_ready: Arc<AtomicBool>,
}

pub enum UdpUpstream {

    Socks5 {
        target: SocketAddr,
        auth: Option<Arc<(String, String)>>,
    },

    Direct {
        resolver: Arc<Resolver>,
        bind_device: Option<String>,
        so_mark: Option<u32>,
    },
}

pub enum Outbound {
    Socks5(Arc<SocksPool>),
    Direct(DirectOutbound),
}

impl Outbound {

    pub fn build(cfg: &Config) -> Arc<Self> {
        let pool_cfg = PoolCfg {
            min: cfg.socks5.pool_min,
            max: cfg.socks5.pool_max,
            idle_timeout: cfg.socks5.pool_idle,
        };
        let ob = &cfg.outbound;
        match ob.mode {

            OutboundMode::Yaml | OutboundMode::Suburl => Arc::new(Outbound::Socks5(Arc::new(
                SocksPool::new(cfg.socks5.server, pool_cfg),
            ))),

            OutboundMode::Socks5 => {
                let target = ob.upstream.unwrap_or(cfg.socks5.server);
                let auth = ob.auth.clone().map(Arc::new);
                Arc::new(Outbound::Socks5(Arc::new(SocksPool::with_auth(
                    target, pool_cfg, auth,
                ))))
            }

            OutboundMode::Free | OutboundMode::Ovpn => {
                let resolver = Arc::new(Resolver::from_cfg(ob.resolver.server));

                let tun_ready = Arc::new(AtomicBool::new(match &ob.bind_device {
                    Some(dev) => device_exists(dev),
                    None => true,
                }));
                Arc::new(Outbound::Direct(DirectOutbound {
                    resolver,
                    bind_device: ob.bind_device.clone(),
                    so_mark: None,
                    tun_ready,
                }))
            }
        }
    }

    pub fn reload(&self, cfg: &Config) {
        if let Outbound::Direct(d) = self {
            d.resolver.set_from_cfg(cfg.outbound.resolver.server);
        }
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, Outbound::Direct(_))
    }

    pub fn tun_ready(&self) -> Option<Arc<AtomicBool>> {
        match self {
            Outbound::Direct(d) if d.bind_device.is_some() => Some(Arc::clone(&d.tun_ready)),
            _ => None,
        }
    }

    pub fn tun_ready_ok(&self) -> bool {
        match self {
            Outbound::Direct(d) if d.bind_device.is_some() => d.tun_ready.load(Ordering::Relaxed),
            _ => true,
        }
    }

    pub fn socks5_pool(&self) -> Option<&Arc<SocksPool>> {
        match self {
            Outbound::Socks5(p) => Some(p),
            Outbound::Direct(_) => None,
        }
    }

    pub fn udp_upstream(&self) -> UdpUpstream {
        match self {
            Outbound::Socks5(p) => UdpUpstream::Socks5 {
                target: p.target(),
                auth: p.auth(),
            },
            Outbound::Direct(d) => UdpUpstream::Direct {
                resolver: Arc::clone(&d.resolver),
                bind_device: d.bind_device.clone(),
                so_mark: d.so_mark,
            },
        }
    }

    pub async fn connect_tcp(
        &self,
        dest: SocketAddr,
        domain: Option<&str>,
    ) -> io::Result<TcpStream> {
        match self {
            Outbound::Socks5(pool) => pool.connect(dest, domain).await.map_err(io::Error::other),
            Outbound::Direct(d) => {

                if !self.tun_ready_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "ovpn tunnel (tun114) not ready",
                    ));
                }
                let addr = match domain {
                    Some(host) => {
                        let ip = d.resolver.resolve_v4(host).await?;
                        SocketAddr::new(std::net::IpAddr::V4(ip), dest.port())
                    }
                    None => dest,
                };
                connect_tcp_direct(
                    addr,
                    d.bind_device.as_deref(),
                    d.so_mark,
                    DIRECT_CONNECT_TIMEOUT,
                )
                .await
                .map_err(io::Error::other)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsResolverCfg, OutboundCfg, SocksCfg};
    use sb_dns::message::parse_query;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    fn cfg_with_outbound(outbound: OutboundCfg, socks_server: SocketAddr) -> Config {
        Config {
            socks5: SocksCfg {
                server: socks_server,
                ..Default::default()
            },
            outbound,
            ..Default::default()
        }
    }

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn mock_dns(answer: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if let Ok(q) = parse_query(&buf[..n]) {
                    let _ = sock.send_to(&q.answer_a(answer, 60), peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn direct_connect_resolves_domain_then_connects() {

        let echo = echo_server().await;
        let dns = mock_dns(Ipv4Addr::LOCALHOST).await;
        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Free,
                resolver: DnsResolverCfg { server: Some(dns) },
                ..Default::default()
            },
            "127.0.0.1:1".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);
        assert!(ob.is_direct() && ob.socks5_pool().is_none());

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), echo.port());
        let mut s = ob.connect_tcp(dest, Some("echo.test")).await.unwrap();
        s.write_all(b"hi-direct").await.unwrap();
        let mut back = [0u8; 9];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hi-direct");
    }

    #[tokio::test]
    async fn ovpn_gate_rejects_before_resolve_when_tun_down() {

        let blackhole: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Ovpn,
                bind_device: Some("tun-nonexistent-zzz".into()),
                resolver: DnsResolverCfg {
                    server: Some(blackhole),
                },
                ..Default::default()
            },
            "127.0.0.1:1".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);

        let gate = ob.tun_ready().expect("ovpn has a gate");
        assert!(!gate.load(Ordering::Relaxed));
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443);
        let start = std::time::Instant::now();
        let err = ob
            .connect_tcp(dest, Some("example.com"))
            .await
            .expect_err("tun down → reject");
        assert_eq!(err.kind(), io::ErrorKind::NetworkUnreachable);

        assert!(start.elapsed() < Duration::from_millis(500));

        let echo = echo_server().await;
        let dns = mock_dns(Ipv4Addr::LOCALHOST).await;

        ob.reload(&cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Ovpn,
                bind_device: Some("tun-nonexistent-zzz".into()),
                resolver: DnsResolverCfg { server: Some(dns) },
                ..Default::default()
            },
            "127.0.0.1:1".parse().unwrap(),
        ));
        gate.store(true, Ordering::Relaxed);

        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), echo.port());
        let err = ob
            .connect_tcp(dest, Some("echo.test"))
            .await
            .expect_err("SO_BINDTODEVICE to missing iface still fails");
        assert_ne!(err.kind(), io::ErrorKind::NetworkUnreachable);
    }

    #[tokio::test]
    async fn direct_connect_literal_ip_no_dns() {
        let echo = echo_server().await;
        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Free,
                ..Default::default()
            },
            "127.0.0.1:1".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);

        let mut s = ob.connect_tcp(echo, None).await.unwrap();
        s.write_all(b"raw!").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"raw!");
    }

    #[tokio::test]
    async fn socks5_mode_builds_pool_with_target_and_auth() {
        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Socks5,
                upstream: Some("9.9.9.9:1080".parse().unwrap()),
                auth: Some(("u".into(), "p".into())),
                ..Default::default()
            },
            "127.0.0.1:1080".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);
        let pool = ob.socks5_pool().expect("socks5 mode has a pool");
        assert_eq!(pool.target(), "9.9.9.9:1080".parse().unwrap());
        assert_eq!(pool.auth().as_deref(), Some(&("u".into(), "p".into())));
        match ob.udp_upstream() {
            UdpUpstream::Socks5 { target, auth } => {
                assert_eq!(target, "9.9.9.9:1080".parse().unwrap());
                assert!(auth.is_some());
            }
            _ => panic!("expected socks5 udp upstream"),
        }
    }

    #[tokio::test]
    async fn direct_reload_swaps_resolver_only() {
        let dns1: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let dns2: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let mut cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Ovpn,
                bind_device: Some("tun114".into()),
                resolver: DnsResolverCfg { server: Some(dns1) },
                ..Default::default()
            },
            "127.0.0.1:1".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);
        let Outbound::Direct(d) = ob.as_ref() else {
            panic!("ovpn → Direct")
        };
        assert_eq!(d.bind_device.as_deref(), Some("tun114"));
        assert_eq!(d.resolver.server(), dns1);

        cfg.outbound.resolver.server = Some(dns2);
        ob.reload(&cfg);
        assert_eq!(d.resolver.server(), dns2);
        assert_eq!(d.bind_device.as_deref(), Some("tun114"));
    }

    #[tokio::test]
    async fn socks5_reload_is_noop() {

        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Yaml,
                ..Default::default()
            },
            "127.0.0.1:1080".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);
        ob.reload(&cfg);
        assert!(ob.socks5_pool().is_some());
    }

    #[tokio::test]
    async fn yaml_mode_targets_clash_no_auth() {
        let cfg = cfg_with_outbound(
            OutboundCfg {
                mode: OutboundMode::Yaml,
                ..Default::default()
            },
            "127.0.0.1:1080".parse().unwrap(),
        );
        let ob = Outbound::build(&cfg);
        let pool = ob.socks5_pool().unwrap();
        assert_eq!(pool.target(), "127.0.0.1:1080".parse().unwrap());
        assert!(pool.auth().is_none());
    }
}
