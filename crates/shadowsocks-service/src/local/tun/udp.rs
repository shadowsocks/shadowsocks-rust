use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use etherparse::{IpHeader, UdpHeader};
use log::{error, trace};
use lru_time_cache::LruCache;
use tokio::sync::mpsc;
use tun::TunPacket;

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

pub struct UdpTun {
    context: Arc<ServiceContext>,
    tun_tx: mpsc::Sender<TunPacket>,
    connections: LruCache<(SocketAddr, SocketAddr), UdpAssociation>,
}

impl UdpTun {
    pub fn new(context: Arc<ServiceContext>, tun_tx: mpsc::Sender<TunPacket>) -> UdpTun {
        UdpTun {
            context,
            tun_tx,
            // Staled connection will be cleared after 24 hours
            connections: LruCache::with_expiry_duration(Duration::from_secs(24 * 60 * 60)),
        }
    }

    pub async fn handle_packet(
        &mut self,
        ip_header: &IpHeader,
        udp_header: &UdpHeader,
        balancer: &PingBalancer,
    ) -> io::Result<(IpHeader, UdpHeader)> {
        unimplemented!()
    }
}

struct UdpAssociation {}
