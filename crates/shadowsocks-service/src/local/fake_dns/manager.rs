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
use log::{error, trace, warn};
use rocksdb::DB as RocksDB;
use tokio::sync::Mutex;

use super::proto;

const FAKE_DNS_MANAGER_STORAGE_VERSION: u32 = 3;

/// Error type of FakeDns manager
#[derive(thiserror::Error, Debug)]
pub enum FakeDnsError {
    /// std::io::Error wrapper
    #[error("{0}")]
    IoError(#[from] io::Error),
    /// rocksdb::Error
    #[error("{0}")]
    RocksDBError(#[from] rocksdb::Error),
}

impl From<FakeDnsError> for io::Error {
    fn from(value: FakeDnsError) -> Self {
        match value {
            FakeDnsError::IoError(e) => e,
            FakeDnsError::RocksDBError(e) => Self::other(e),
        }
    }
}

/// FakeDns Api Result type
pub type FakeDnsResult<T> = Result<T, FakeDnsError>;

/// Fake DNS manager
pub struct FakeDnsManager {
    db: Mutex<RocksDB>,
    ipv4_network: Mutex<Cycle<Ipv4AddrRange>>,
    ipv6_network: Mutex<Cycle<Ipv6AddrRange>>,
    expire_duration: Duration,
}

macro_rules! map_domain_ip {
    ($self:ident, $domain:ident, $addr_ty:ty, $addr_field:ident, $network_field:ident) => {{
        let db = $self.db.lock().await;
        let name2ip_key = FakeDnsManager::get_name2ip_key($domain);

        loop {
            let mut domain_name_mapping = proto::DomainNameMapping::default();

            if let Some(v) = db.get(&name2ip_key)? {
                domain_name_mapping = proto::DomainNameMapping::decode(&v)?;

                if !domain_name_mapping.$addr_field.is_empty() {
                    match domain_name_mapping.$addr_field.parse::<$addr_ty>() {
                        Ok(i) => {
                            let now = FakeDnsManager::get_current_timestamp();
                            let expire_secs =
                                FakeDnsManager::get_current_timestamp() + $self.expire_duration.as_secs() as i64;

                            if domain_name_mapping.expire_time >= now {
                                // Not expired yet.
                                domain_name_mapping.expire_time = expire_secs;
                                let nv = domain_name_mapping.encode_to_vec()?;

                                db.put(&name2ip_key, nv)?;
                                trace!(
                                    "fakedns mapping {} -> {}, expires {}",
                                    $domain, i, domain_name_mapping.expire_time
                                );
                                return Ok((i, $self.expire_duration));
                            } else {
                                // Expired. Try to reuse.

                                let ip2name_key = FakeDnsManager::get_ip2name_key(i.into());
                                if let Some(v) = db.get(&ip2name_key)? {
                                    let mut ip_mapping = proto::IpAddrMapping::decode(&v)?;
                                    if ip_mapping.domain_name == $domain.to_string() {
                                        // Try to extend its expire time
                                        ip_mapping.expire_time = expire_secs;
                                        let nv = ip_mapping.encode_to_vec()?;

                                        db.put(&ip2name_key, nv)?;
                                        trace!(
                                            "fakedns mapping {} -> {}, expires {}",
                                            $domain, i, domain_name_mapping.expire_time
                                        );
                                        return Ok((i, $self.expire_duration));
                                    }
                                }
                            }
                        }
                        Err(..) => {
                            warn!("failed to parse {}, going to replace", domain_name_mapping.$addr_field);
                        }
                    }
                }
            }

            // Allocate a new IPv4 address for this domain
            while let Some(ip) = $self.$network_field.lock().await.next() {
                let ip2name_key = FakeDnsManager::get_ip2name_key(ip.into());

                if let Some(v) = db.get(&ip2name_key)? {
                    let ip_mapping = proto::IpAddrMapping::decode(&v)?;

                    let now = FakeDnsManager::get_current_timestamp();
                    if ip_mapping.expire_time > now {
                        continue;
                    }
                }

                let mut ip_mapping = proto::IpAddrMapping::default();

                let expire_secs = FakeDnsManager::get_current_timestamp() + $self.expire_duration.as_secs() as i64;
                ip_mapping.expire_time = expire_secs;
                ip_mapping.domain_name = $domain.to_string();

                let nv = ip_mapping.encode_to_vec()?;

                db.put(&ip2name_key, nv)?;
                // Replace name2ip

                domain_name_mapping.$addr_field = ip.to_string();
                domain_name_mapping.expire_time = ip_mapping.expire_time;
                let nv = domain_name_mapping.encode_to_vec()?;

                db.put(&name2ip_key, nv)?;
                trace!(
                    "fakedns mapping {} -> {}, expires {} created",
                    $domain, ip, domain_name_mapping.expire_time
                );

                return Ok((ip, $self.expire_duration));
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
    ) -> FakeDnsResult<Self> {
        let db_path = db_path.as_ref();

        // https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning
        let mut db_options = rocksdb::Options::default();
        db_options.create_if_missing(true);
        db_options.set_compression_type(rocksdb::DBCompressionType::Zstd);
        db_options.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        db_options.set_bottommost_zstd_max_train_bytes(0, true);
        db_options.set_max_background_jobs(6);
        db_options.set_bytes_per_sync(1048576);
        db_options.set_compaction_pri(rocksdb::CompactionPri::MinOverlappingRatio);
        let mut db = match RocksDB::open(&db_options, db_path) {
            Ok(db) => db,
            Err(err) => {
                error!("failed to open rocksdb, path: {}, error: {}", db_path.display(), err);
                return Err(err.into());
            }
        };

        let ipv4_network_str = ipv4_network.to_string();
        let ipv6_network_str = ipv6_network.to_string();

        let mut recreate_database = true;

        let key = "shadowsocks_fakedns_meta";
        match db.get(key) {
            Ok(Some(v)) => {
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
            Ok(None) => {
                // New DB without an META
            }
            Err(err) => {
                error!("failed to get {}, error: {}", key, err);
                return Err(err.into());
            }
        }

        if recreate_database {
            drop(db);
            let _ = RocksDB::destroy(&db_options, db_path);

            // Re-create by Open
            db = match RocksDB::open(&db_options, db_path) {
                Ok(db) => db,
                Err(err) => {
                    error!(
                        "failed to recreate rocksdb, path: {}, error: {}",
                        db_path.display(),
                        err
                    );
                    return Err(err.into());
                }
            };

            let c = proto::StorageMeta {
                ipv4_network: ipv4_network_str,
                ipv6_network: ipv6_network_str,
                version: FAKE_DNS_MANAGER_STORAGE_VERSION,
            };

            let v = c.encode_to_vec()?;
            if let Err(err) = db.put(key, v) {
                error!("failed to init storage, key: {}, error: {}", key, err);
                return Err(err.into());
            }

            trace!("FakeDNS database created. {:?}", c);
        }

        Ok(Self {
            db: Mutex::new(db),
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
    pub async fn map_domain_ipv4(&self, domain: &Name) -> FakeDnsResult<(Ipv4Addr, Duration)> {
        map_domain_ip!(self, domain, Ipv4Addr, ipv4_addr, ipv4_network)
    }

    /// Get or create an IPv6 mapping for `domain`
    pub async fn map_domain_ipv6(&self, domain: &Name) -> FakeDnsResult<(Ipv6Addr, Duration)> {
        map_domain_ip!(self, domain, Ipv6Addr, ipv6_addr, ipv6_network)
    }

    /// Get IP mapped domain name
    pub async fn map_ip_domain(&self, ip: IpAddr) -> FakeDnsResult<Option<Name>> {
        let db = self.db.lock().await;

        // ip -> domain_name
        let ip2name_key = Self::get_ip2name_key(ip);
        match db.get(&ip2name_key)? {
            None => Ok(None),
            Some(v) => {
                // Got ip -> domain_name

                let mut ip_mapping = proto::IpAddrMapping::decode(&v)?;
                let now = Self::get_current_timestamp();
                if ip_mapping.expire_time >= now {
                    // Ok. It is not expired yet. Try to extend its expire time.
                    ip_mapping.expire_time = now + self.expire_duration.as_secs() as i64;
                    let nv = ip_mapping.encode_to_vec()?;
                    db.put(&ip2name_key, nv)?;

                    // Update name2ip's expire time

                    let name = match ip_mapping.domain_name.parse::<Name>() {
                        Ok(n) => n,
                        Err(..) => return Ok(None),
                    };

                    {
                        let name2ip_key = Self::get_name2ip_key(&name);
                        match db.get(&name2ip_key)? {
                            Some(v) => {
                                let mut domain_name_mapping = proto::DomainNameMapping::decode(&v)?;
                                domain_name_mapping.expire_time = ip_mapping.expire_time;
                                let nv = domain_name_mapping.encode_to_vec()?;
                                db.put(&name2ip_key, nv)?;
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
