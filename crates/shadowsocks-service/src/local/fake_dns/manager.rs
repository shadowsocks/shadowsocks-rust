//! Fake DNS manager

use std::{
    io,
    iter::Cycle,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    time::{Duration, SystemTime},
};

use hickory_resolver::proto::rr::Name;
use ipnet::{Ipv4AddrRange, Ipv4Net, Ipv6AddrRange, Ipv6Net};
use log::{trace, warn};
use sled::{Config as SledConfig, Db as SledDatabase};
use tokio::sync::Mutex;

use super::proto;

const FAKE_DNS_MANAGER_STORAGE_VERSION: u32 = 2;

/// Fake DNS manager
pub struct FakeDnsManager {
    db: SledDatabase,
    ipv4_network: Mutex<Cycle<Ipv4AddrRange>>,
    ipv6_network: Mutex<Cycle<Ipv6AddrRange>>,
    expire_duration: Duration,
}

macro_rules! map_domain_ip {
    ($self:ident, $domain:ident, $addr_ty:ty, $addr_field:ident, $network_field:ident) => {{
        let name2ip_key = FakeDnsManager::get_name2ip_key($domain);

        loop {
            let name2ip_value = $self.db.get(&name2ip_key)?;

            let mut domain_name_mapping = proto::DomainNameMapping::default();

            if let Some(ref v) = name2ip_value {
                domain_name_mapping = proto::DomainNameMapping::decode(v)?;

                if !domain_name_mapping.$addr_field.is_empty() {
                    match domain_name_mapping.$addr_field.parse::<$addr_ty>() {
                        Ok(i) => {
                            let now = FakeDnsManager::get_current_timestamp();
                            let expire_secs =
                                FakeDnsManager::get_current_timestamp() + $self.expire_duration.as_secs() as i64;

                            let mut reallocate = true;
                            if domain_name_mapping.expire_time >= now {
                                // Not expired yet.
                                reallocate = false;
                            } else {
                                // Expired. Try to reuse.

                                let ip2name_key = FakeDnsManager::get_ip2name_key(i.into());
                                let ip2name_value = $self.db.get(&ip2name_key)?;
                                if let Some(ref v) = ip2name_value {
                                    let mut ip_mapping = proto::IpAddrMapping::decode(v)?;
                                    if ip_mapping.domain_name == $domain.to_string() {
                                        // Try to extend its expire time
                                        ip_mapping.expire_time = expire_secs;
                                        let nv = ip_mapping.encode_to_vec()?;
                                        if let Ok(..) =
                                            $self
                                                .db
                                                .compare_and_swap(&ip2name_key, ip2name_value.as_ref(), Some(nv))
                                        {
                                            reallocate = false;
                                        } else {
                                            // CAS Failed, retry
                                            continue;
                                        }
                                    }
                                }
                            }

                            if !reallocate {
                                domain_name_mapping.expire_time = expire_secs;
                                let nv = domain_name_mapping.encode_to_vec()?;

                                // Ignore update error. It is ok if expire_time is updated by another thread.
                                let _ = $self
                                    .db
                                    .compare_and_swap(&name2ip_key, name2ip_value.as_ref(), Some(nv));
                                trace!(
                                    "fakedns mapping {} -> {}, expires {}",
                                    $domain,
                                    i,
                                    domain_name_mapping.expire_time
                                );
                                return Ok((i, $self.expire_duration));
                            }
                        }
                        Err(..) => {
                            warn!("failed to parse {}, going to replace", domain_name_mapping.$addr_field);
                        }
                    }
                }
            }

            // Allocate a new IPv4 address for this domain
            'alloc_network: while let Some(ip) = $self.$network_field.lock().await.next() {
                let ip2name_key = FakeDnsManager::get_ip2name_key(ip.into());

                loop {
                    let ip2name_value = $self.db.get(&ip2name_key)?;
                    if let Some(ref v) = ip2name_value {
                        let ip_mapping = proto::IpAddrMapping::decode(v)?;

                        let now = FakeDnsManager::get_current_timestamp();
                        if ip_mapping.expire_time > now {
                            break;
                        }
                    }

                    let mut ip_mapping = proto::IpAddrMapping::default();

                    let expire_secs = FakeDnsManager::get_current_timestamp() + $self.expire_duration.as_secs() as i64;
                    ip_mapping.expire_time = expire_secs;
                    ip_mapping.domain_name = $domain.to_string();

                    let nv = ip_mapping.encode_to_vec()?;

                    if let Ok(..) = $self.db.compare_and_swap(&ip2name_key, ip2name_value, Some(nv.clone())) {
                        // Replace name2ip

                        domain_name_mapping.$addr_field = ip.to_string();
                        domain_name_mapping.expire_time = ip_mapping.expire_time;
                        let nv = domain_name_mapping.encode_to_vec()?;

                        if let Ok(..) = $self
                            .db
                            .compare_and_swap(&name2ip_key, name2ip_value.as_ref(), Some(nv))
                        {
                            trace!(
                                "fakedns mapping {} -> {}, expires {} created",
                                $domain,
                                ip,
                                domain_name_mapping.expire_time
                            );

                            return Ok((ip, $self.expire_duration));
                        } else {
                            // name2ip CAS failed. Some other thread already allocated an address for this name.
                            let _ = $self.db.remove(&ip2name_key);
                            break 'alloc_network;
                        }
                    }
                }
            }
        }
    }};
}

impl FakeDnsManager {
    pub fn open<P: AsRef<Path>>(
        db_path: P,
        ipv4_network: Ipv4Net,
        ipv6_network: Ipv6Net,
        expire_duration: Duration,
    ) -> io::Result<FakeDnsManager> {
        let db = SledConfig::new()
            .cache_capacity(10 * 1024 * 1024)
            .mode(sled::Mode::HighThroughput)
            .flush_every_ms(Some(1_000))
            .path(db_path)
            .open()?;

        let ipv4_network_str = ipv4_network.to_string();
        let ipv6_network_str = ipv6_network.to_string();

        let mut recreate_database = true;

        let key = "shadowsocks_fakedns_meta";
        if let Some(v) = db.get(key)? {
            if let Ok(c) = proto::StorageMeta::decode(&v) {
                if c.version == FAKE_DNS_MANAGER_STORAGE_VERSION {
                    if ipv4_network_str != c.ipv4_network || ipv6_network_str != c.ipv6_network {
                        warn!(
                            "IPv4 network {} (storage {}), IPv6 network {} (storage {}) not match",
                            ipv4_network_str, c.ipv4_network, ipv6_network_str, c.ipv6_network
                        );
                    } else {
                        recreate_database = false;
                    }
                } else {
                    warn!("storage version {} not match, recreating database", c.version);
                }
            } else {
                warn!("storage meta parse failed. recreating database");
            }
        }

        if recreate_database {
            let _ = db.clear();

            let c = proto::StorageMeta {
                ipv4_network: ipv4_network_str,
                ipv6_network: ipv6_network_str,
                version: FAKE_DNS_MANAGER_STORAGE_VERSION,
            };

            let v = c.encode_to_vec()?;
            db.insert(key, v)?;

            trace!("FakeDNS database created. {:?}", c);
        }

        Ok(FakeDnsManager {
            db,
            ipv4_network: Mutex::new(ipv4_network.hosts().cycle()),
            ipv6_network: Mutex::new(ipv6_network.hosts().cycle()),
            expire_duration,
        })
    }

    #[inline]
    fn get_current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime")
            .as_secs() as i64
    }

    #[inline]
    fn get_name2ip_key(domain: &Name) -> String {
        format!("shadowsocks_fakedns_name2ip_{domain}")
    }

    #[inline]
    fn get_ip2name_key(ip: IpAddr) -> String {
        format!("shadowsocks_fakedns_ip2name_{ip}")
    }

    /// Get or create an IPv4 mapping for `domain`
    pub async fn map_domain_ipv4(&self, domain: &Name) -> io::Result<(Ipv4Addr, Duration)> {
        map_domain_ip!(self, domain, Ipv4Addr, ipv4_addr, ipv4_network)
    }

    /// Get or create an IPv6 mapping for `domain`
    pub async fn map_domain_ipv6(&self, domain: &Name) -> io::Result<(Ipv6Addr, Duration)> {
        map_domain_ip!(self, domain, Ipv6Addr, ipv6_addr, ipv6_network)
    }

    /// Get IP mapped domain name
    pub async fn map_ip_domain(&self, ip: IpAddr) -> io::Result<Option<Name>> {
        let ip2name_key = FakeDnsManager::get_ip2name_key(ip);

        let ip2name_value = self.db.get(&ip2name_key)?;
        match ip2name_value {
            None => Ok(None),
            Some(ref v) => {
                let mut ip_mapping = proto::IpAddrMapping::decode(v)?;

                let now = FakeDnsManager::get_current_timestamp();
                if ip_mapping.expire_time >= now {
                    // Ok. It is not expired yet. Try to extend its expire time.
                    ip_mapping.expire_time = now + self.expire_duration.as_secs() as i64;
                    let nv = ip_mapping.encode_to_vec()?;
                    let _ = self
                        .db
                        .compare_and_swap(&ip2name_key, ip2name_value.as_ref(), Some(nv))?;

                    // Update name2ip's expire time

                    let name = match ip_mapping.domain_name.parse::<Name>() {
                        Ok(n) => n,
                        Err(..) => return Ok(None),
                    };

                    {
                        let name2ip_key = FakeDnsManager::get_name2ip_key(&name);
                        let name2ip_value = self.db.get(&name2ip_key)?;
                        match name2ip_value {
                            Some(ref v) => {
                                let mut domain_name_mapping = proto::DomainNameMapping::decode(v)?;
                                domain_name_mapping.expire_time = ip_mapping.expire_time;
                                let nv = domain_name_mapping.encode_to_vec()?;
                                let _ = self.db.compare_and_swap(&name2ip_key, name2ip_value.as_ref(), Some(nv));
                            }
                            None => {
                                // Interesting. No name2ip.
                                return Ok(None);
                            }
                        }
                    }

                    Ok(Some(name))
                } else {
                    Ok(None)
                }
            }
        }
    }
}
