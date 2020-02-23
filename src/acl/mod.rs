//! Access Control List (ACL) for shadowsocks
//!
//! This is for advance controlling server behaviors in both local and proxy servers.

use std::{
    cmp::Ordering,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, Error, ErrorKind},
    net::SocketAddr,
    path::Path,
};

use ipnetwork::IpNetwork;
use regex::RegexSet;

use crate::{context::Context, relay::socks5::Address};

/// Strategy mode that ACL is running
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    /// BlackList mode, rejects or bypasses all requests by default
    BlackList,
    /// WhiteList mode, accepts or proxies all requests by default
    WhiteList,
}

#[derive(Clone)]
struct Rules {
    ip: Vec<IpNetwork>,
    rule: RegexSet,
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rules {{ ip: {}, rule: {} }}", self.ip.len(), self.rule.len())
    }
}

impl Rules {
    /// Create a new rule
    fn new(mut ip: Vec<IpNetwork>, rule: RegexSet) -> Rules {
        // Sort networks for binary search
        // TODO: Merge duplicated subnets
        ip.sort_unstable();

        Rules { ip, rule }
    }

    /// Check if the specified address matches these rules
    fn check_address_matched(&self, addr: &Address) -> bool {
        match *addr {
            Address::SocketAddress(ref saddr) => self.check_ip_matched(saddr),
            Address::DomainNameAddress(ref domain, ..) => self.check_host_matched(domain),
        }
    }

    /// Check if the specified address matches any rules
    fn check_ip_matched(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        let ip_network = IpNetwork::from(ip); // Create a network which only contains itself

        self.ip
            .binary_search_by(|network| {
                if network.contains(ip) {
                    Ordering::Equal
                } else {
                    network.cmp(&ip_network)
                }
            })
            .is_ok()
    }

    /// Check if the specified host matches any rules
    fn check_host_matched(&self, host: &str) -> bool {
        self.rule.is_match(host)
    }
}

/// ACL rules
///
/// ## Sections
///
/// ACL File is formatted in sections, each section has a name with surrounded by brackets `[` and `]`
/// followed by Rules line by line.
///
/// ```plain
/// [SECTION-1]
/// RULE-1
/// RULE-2
/// RULE-3
///
/// [SECTION-2]
/// RULE-1
/// RULE-2
/// RULE-3
/// ```
///
/// Available sections are
///
/// - For local servers (`sslocal`, `sstunnel`, ...)
///     * `[bypass_all]` - ACL runs in `BlackList` mode.
///         - `[bypass_list]` - Rules for connecting directly
///     * `[proxy_all]` - ACL runs in `WhiteList` mode.
///         - `[proxy_list]` - Rules for connecting through proxies
/// - For remote servers (`ssserver`)
///     * `[reject_all]` - ACL runs in `BlackList` mode.
///     * `[accept_all]` - ACL runs in `WhiteList` mode.
///     * `[outbound_block_list]` - Rules for blocking outbound addresses.
///
/// ## Mode
///
/// - `WhiteList` (reject / bypass all, except ...)
///
/// Only hosts / clients that matches rules in
///     - `[proxy_list]` - will be connected through remote proxies, others will be connected directly
///     - `[white_list]` - will be allowed, others will be rejected
///
/// - `BlackList` (accept / proxy all, except ...)
///
/// Only hosts / clients that matches rules in
///     - `[bypass_list]` - will be connected directly instead of connecting through remote proxies
///     - `[black_list]` - will be rejected (close connection)
///
/// ## Rules
///
/// Rules can be either
///
/// - CIDR form network addresses, like `10.9.0.32/16`
/// - IP addresses, like `127.0.0.1` or `::1`
/// - Regular Expression for matching hosts, like `(^|\.)gmail\.com$`
#[derive(Debug, Clone)]
pub struct AccessControl {
    outbound_block: Rules,
    black_list: Rules,
    white_list: Rules,
    mode: Mode,
}

impl AccessControl {
    /// Load ACL rules from a file
    pub fn load_from_file<P: AsRef<Path>>(p: P) -> io::Result<AccessControl> {
        let fp = File::open(p)?;
        let r = BufReader::new(fp);

        let mut mode = Mode::BlackList;

        let mut outbound_block_network = Vec::new();
        let mut outbound_block_rules = Vec::new();
        let mut bypass_network = Vec::new();
        let mut bypass_rules = Vec::new();
        let mut proxy_network = Vec::new();
        let mut proxy_rules = Vec::new();

        let mut curr_network = &mut bypass_network;
        let mut curr_rules = &mut proxy_rules;

        for line in r.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            match line.as_str() {
                "[reject_all]" | "[bypass_all]" => {
                    mode = Mode::WhiteList;
                }
                "[accept_all]" | "[proxy_all]" => {
                    mode = Mode::BlackList;
                }
                "[outbound_block_list]" => {
                    curr_network = &mut outbound_block_network;
                    curr_rules = &mut outbound_block_rules;
                }
                "[black_list]" | "[bypass_list]" => {
                    curr_network = &mut bypass_network;
                    curr_rules = &mut bypass_rules;
                }
                "[white_list]" | "[proxy_list]" => {
                    curr_network = &mut proxy_network;
                    curr_rules = &mut proxy_rules;
                }
                _ => {
                    match line.parse::<IpNetwork>() {
                        Ok(network) => curr_network.push(network),
                        Err(..) => {
                            // FIXME: If this line is not a valid regex, how can we know without actually compile it?
                            curr_rules.push(line);
                        }
                    }
                }
            }
        }

        let outbound_block_regex = match RegexSet::new(outbound_block_rules) {
            Ok(r) => r,
            Err(err) => {
                let err = Error::new(ErrorKind::Other, format!("[outbound_block_list] regex error: {}", err));
                return Err(err);
            }
        };

        let bypass_regex = match RegexSet::new(bypass_rules) {
            Ok(r) => r,
            Err(err) => {
                let err = Error::new(
                    ErrorKind::Other,
                    format!("[black_list] or [bypass_list] regex error: {}", err),
                );
                return Err(err);
            }
        };

        let proxy_regex = match RegexSet::new(proxy_rules) {
            Ok(r) => r,
            Err(err) => {
                let err = Error::new(
                    ErrorKind::Other,
                    format!("[white_list] or [proxy_list] regex error: {}", err),
                );
                return Err(err);
            }
        };

        Ok(AccessControl {
            outbound_block: Rules::new(outbound_block_network, outbound_block_regex),
            black_list: Rules::new(bypass_network, bypass_regex),
            white_list: Rules::new(proxy_network, proxy_regex),
            mode,
        })
    }

    /// Check if target address should be bypassed (for client)
    ///
    /// FIXME: This function may perform a DNS resolution
    pub async fn check_target_bypassed(&self, context: &Context, addr: &Address) -> bool {
        match self.mode {
            Mode::BlackList => {
                // Only hosts in bypass_list will be bypassed
                if self.black_list.check_address_matched(addr) {
                    return true;
                }

                if let Address::DomainNameAddress(ref host, port) = *addr {
                    if let Ok(vaddr) = context.dns_resolve(host, port).await {
                        for addr in vaddr {
                            if self.black_list.check_ip_matched(&addr) {
                                return true;
                            }
                        }
                    }
                }

                false
            }
            Mode::WhiteList => {
                // Only hosts in proxy_list will be proxied
                if self.white_list.check_address_matched(addr) {
                    return false;
                }

                if let Address::DomainNameAddress(ref host, port) = *addr {
                    if let Ok(vaddr) = context.dns_resolve(host, port).await {
                        for addr in vaddr {
                            if self.white_list.check_ip_matched(&addr) {
                                return false;
                            }
                        }
                    }
                }

                true
            }
        }
    }

    /// Check if client address should be blocked (for server)
    pub fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.mode {
            Mode::BlackList => {
                // Only clients in black_list will be blocked
                self.black_list.check_ip_matched(addr)
            }
            Mode::WhiteList => {
                // Only clients in white_list will be proxied
                !self.white_list.check_ip_matched(addr)
            }
        }
    }

    /// Check if outbound address is blocked (for server)
    ///
    /// NOTE: `Address::DomainName` is only validated by regex rules,
    ///       resolved addresses are checked in the `lookup_outbound_then!` macro
    pub fn check_outbound_blocked(&self, outbound: &Address) -> bool {
        self.outbound_block.check_address_matched(outbound)
    }

    /// Check resolved outbound address is blocked (for server)
    pub fn check_resolved_outbound_blocked(&self, outbound: &SocketAddr) -> bool {
        self.outbound_block.check_ip_matched(outbound)
    }
}
