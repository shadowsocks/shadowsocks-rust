//! Access Control List (ACL) for shadowsocks
//!
//! This is for advance controlling server behaviors in both local and proxy servers.

use std::{
    borrow::Cow,
    collections::HashSet,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, Error},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str,
    sync::LazyLock,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use log::{trace, warn};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

use shadowsocks::{context::Context, relay::socks5::Address};

use self::sub_domains_tree::SubDomainsTree;

mod sub_domains_tree;

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
    ipv4: IpRange<Ipv4Net>,
    ipv6: IpRange<Ipv6Net>,
    rule_regex: RegexSet,
    rule_set: HashSet<String>,
    rule_tree: SubDomainsTree,
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Rules {{ ipv4: {:?}, ipv6: {:?}, rule_regex: [",
            self.ipv4, self.ipv6
        )?;

        let max_len = 2;
        let has_more = self.rule_regex.len() > max_len;

        for (idx, r) in self.rule_regex.patterns().iter().take(max_len).enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            f.write_str(r)?;
        }

        if has_more {
            f.write_str(", ...")?;
        }

        write!(f, "], rule_set: [")?;

        let has_more = self.rule_set.len() > max_len;
        for (idx, r) in self.rule_set.iter().take(max_len).enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            f.write_str(r)?;
        }

        if has_more {
            f.write_str(", ...")?;
        }

        write!(f, "], rule_tree: {:?} }}", self.rule_tree)
    }
}

impl Rules {
    /// Create a new rule
    fn new(
        mut ipv4: IpRange<Ipv4Net>,
        mut ipv6: IpRange<Ipv6Net>,
        rule_regex: RegexSet,
        rule_set: HashSet<String>,
        rule_tree: SubDomainsTree,
    ) -> Self {
        // Optimization, merging networks
        ipv4.simplify();
        ipv6.simplify();

        Self {
            ipv4,
            ipv6,
            rule_regex,
            rule_set,
            rule_tree,
        }
    }

    /// Check if the specified address matches these rules
    #[allow(dead_code)]
    fn check_address_matched(&self, addr: &Address) -> bool {
        match *addr {
            Address::SocketAddress(ref saddr) => self.check_ip_matched(&saddr.ip()),
            Address::DomainNameAddress(ref domain, ..) => self.check_host_matched(domain),
        }
    }

    /// Check if the specified address matches any rules
    fn check_ip_matched(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                if self.ipv4.contains(v4) {
                    return true;
                }

                let mapped_ipv6 = v4.to_ipv6_mapped();
                self.ipv6.contains(&mapped_ipv6)
            }
            IpAddr::V6(v6) => {
                if self.ipv6.contains(v6) {
                    return true;
                }

                if let Some(mapped_ipv4) = v6.to_ipv4_mapped() {
                    return self.ipv4.contains(&mapped_ipv4);
                }

                false
            }
        }
    }

    /// Check if the specified ASCII host matches any rules
    fn check_host_matched(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.'); // FQDN, removes the last `.`
        self.rule_set.contains(host) || self.rule_tree.contains(host) || self.rule_regex.is_match(host.as_bytes())
    }

    /// Check if there are no rules for IP addresses
    fn is_ip_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    /// Check if there are no rules for domain names
    fn is_host_empty(&self) -> bool {
        self.rule_set.is_empty() && self.rule_tree.is_empty() && self.rule_regex.is_empty()
    }
}

struct ParsingRules {
    name: &'static str,
    ipv4: IpRange<Ipv4Net>,
    ipv6: IpRange<Ipv6Net>,
    rules_regex: Vec<String>,
    rules_set: HashSet<String>,
    rules_tree: SubDomainsTree,
}

impl ParsingRules {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            ipv4: IpRange::new(),
            ipv6: IpRange::new(),
            rules_regex: Vec::new(),
            rules_set: HashSet::new(),
            rules_tree: SubDomainsTree::new(),
        }
    }

    fn add_ipv4_rule(&mut self, rule: impl Into<Ipv4Net>) {
        let rule = rule.into();
        trace!("IPV4-RULE {}", rule);
        self.ipv4.add(rule);
    }

    fn add_ipv6_rule(&mut self, rule: impl Into<Ipv6Net>) {
        let rule = rule.into();
        trace!("IPV6-RULE {}", rule);
        self.ipv6.add(rule);
    }

    fn add_regex_rule(&mut self, mut rule: String) {
        static TREE_SET_RULE_EQUIV: LazyLock<Regex> = LazyLock::new(|| {
            RegexBuilder::new(
                r#"^(?:(?:\((?:\?:)?\^\|\\\.\)|(?:\^\.(?:\+|\*))?\\\.)((?:[\w-]+(?:\\\.)?)+)|\^((?:[\w-]+(?:\\\.)?)+))\$?$"#,
            )
            .unicode(false)
            .build()
            .unwrap()
        });

        if let Some(caps) = TREE_SET_RULE_EQUIV.captures(rule.as_bytes()) {
            if let Some(tree_rule) = caps.get(1) {
                if let Ok(tree_rule) = str::from_utf8(tree_rule.as_bytes()) {
                    let tree_rule = tree_rule.replace("\\.", ".");
                    if self.add_tree_rule_inner(&tree_rule).is_ok() {
                        trace!("REGEX-RULE {} => TREE-RULE {}", rule, tree_rule);
                        return;
                    }
                }
            } else if let Some(set_rule) = caps.get(2) {
                if let Ok(set_rule) = str::from_utf8(set_rule.as_bytes()) {
                    let set_rule = set_rule.replace("\\.", ".");
                    if self.add_set_rule_inner(&set_rule).is_ok() {
                        trace!("REGEX-RULE {} => SET-RULE {}", rule, set_rule);
                        return;
                    }
                }
            }
        }

        trace!("REGEX-RULE {}", rule);

        rule.make_ascii_lowercase();

        // Handle it as a normal REGEX
        // FIXME: If this line is not a valid regex, how can we know without actually compile it?
        self.rules_regex.push(rule);
    }

    #[inline]
    fn add_set_rule(&mut self, rule: &str) -> io::Result<()> {
        trace!("SET-RULE {}", rule);
        self.add_set_rule_inner(rule)
    }

    fn add_set_rule_inner(&mut self, rule: &str) -> io::Result<()> {
        self.rules_set.insert(self.check_is_ascii(rule)?.to_ascii_lowercase());
        Ok(())
    }

    #[inline]
    fn add_tree_rule(&mut self, rule: &str) -> io::Result<()> {
        trace!("TREE-RULE {}", rule);
        self.add_tree_rule_inner(rule)
    }

    fn add_tree_rule_inner(&mut self, rule: &str) -> io::Result<()> {
        // SubDomainsTree do lowercase conversion inside insert
        self.rules_tree.insert(self.check_is_ascii(rule)?);
        Ok(())
    }

    fn check_is_ascii<'a>(&self, str: &'a str) -> io::Result<&'a str> {
        if str.is_ascii() {
            // Remove the last `.` of FQDN
            Ok(str.trim_end_matches('.'))
        } else {
            Err(Error::other(format!(
                "{} parsing error: Unicode not allowed here `{}`",
                self.name, str
            )))
        }
    }

    fn compile_regex(name: &'static str, regex_rules: Vec<String>) -> io::Result<RegexSet> {
        const REGEX_SIZE_LIMIT: usize = usize::MAX;
        RegexSetBuilder::new(regex_rules)
            .size_limit(REGEX_SIZE_LIMIT)
            .unicode(false)
            .build()
            .map_err(|err| Error::other(format!("{name} regex error: {err}")))
    }

    fn into_rules(self) -> io::Result<Rules> {
        Ok(Rules::new(
            self.ipv4,
            self.ipv6,
            Self::compile_regex(self.name, self.rules_regex)?,
            self.rules_set,
            self.rules_tree,
        ))
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
/// - For local servers (`sslocal`, `ssredir`, ...)
///     * `[bypass_all]` - ACL runs in `WhiteList` mode.
///     * `[proxy_all]` - ACL runs in `BlackList` mode.
///     * `[bypass_list]` - Rules for connecting directly
///     * `[proxy_list]` - Rules for connecting through proxies
/// - For remote servers (`ssserver`)
///     * `[reject_all]` - ACL runs in `WhiteList` mode.
///     * `[accept_all]` - ACL runs in `BlackList` mode.
///     * `[black_list]` - Rules for rejecting
///     * `[white_list]` - Rules for allowing
///     * `[outbound_block_all]` - ACL runs in `WhiteList` mode for outbound addresses.
///     * `[outbound_allow_all]` - ACL runs in `BlackList` mode for outbound addresses.
///     * `[outbound_block_list]` - Rules for blocking outbound addresses.
///     * `[outbound_allow_list]` - Rules for allowing outbound addresses.
///
/// ## Mode
///
/// Mode is the default ACL strategy for those addresses that are not in configuration file.
///
/// - `BlackList` - Bypasses / Rejects all addresses except those in `[proxy_list]` or `[white_list]`
/// - `WhiteList` - Proxies / Accepts all addresses except those in `[bypass_list]` or `[black_list]`
///
/// ## Rules
///
/// Rules can be either
///
/// - CIDR form network addresses, like `10.9.0.32/16`
/// - IP addresses, like `127.0.0.1` or `::1`
/// - Regular Expression for matching hosts, like `(^|\.)gmail\.com$`
/// - Domain with preceding `|` for exact matching, like `|google.com`
/// - Domain with preceding `||` for matching with subdomains, like `||google.com`
#[derive(Debug, Clone)]
pub struct AccessControl {
    outbound_block: Rules,
    outbound_allow: Rules,
    black_list: Rules,
    white_list: Rules,
    mode: Mode,
    outbound_mode: Mode,
    file_path: PathBuf,
}

impl AccessControl {
    /// Load ACL rules from a file
    pub fn load_from_file<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        trace!("ACL loading from {:?}", p.as_ref());

        let file_path_ref = p.as_ref();
        let file_path = file_path_ref.to_path_buf();

        let fp = File::open(file_path_ref)?;
        let r = BufReader::new(fp);

        let mut mode = Mode::BlackList;
        let mut outbound_mode = Mode::BlackList;

        let mut outbound_block = ParsingRules::new("[outbound_block_list]");
        let mut outbound_allow = ParsingRules::new("[outbound_allow_list]");
        let mut bypass = ParsingRules::new("[black_list] or [bypass_list]");
        let mut proxy = ParsingRules::new("[white_list] or [proxy_list]");
        let mut curr = &mut bypass;

        trace!("ACL parsing start from mode {:?} and black_list / bypass_list", mode);

        for line in r.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            // Comments
            if line.starts_with('#') {
                continue;
            }

            let line = line.trim();

            if !line.is_ascii() {
                warn!("ACL rule {} containing non-ASCII characters, skipped", line);
                continue;
            }

            if let Some(rule) = line.strip_prefix("||") {
                curr.add_tree_rule(rule)?;
                continue;
            }

            if let Some(rule) = line.strip_prefix('|') {
                curr.add_set_rule(rule)?;
                continue;
            }

            match line {
                "[reject_all]" | "[bypass_all]" => {
                    mode = Mode::WhiteList;
                    trace!("switch to mode {:?}", mode);
                }
                "[accept_all]" | "[proxy_all]" => {
                    mode = Mode::BlackList;
                    trace!("switch to mode {:?}", mode);
                }
                "[outbound_block_all]" => {
                    outbound_mode = Mode::WhiteList;
                    trace!("switch to outbound_mode {:?}", outbound_mode);
                }
                "[outbound_allow_all]" => {
                    outbound_mode = Mode::BlackList;
                    trace!("switch to outbound_mode {:?}", outbound_mode);
                }
                "[outbound_block_list]" => {
                    curr = &mut outbound_block;
                    trace!("loading outbound_block_list");
                }
                "[outbound_allow_list]" => {
                    curr = &mut outbound_allow;
                    trace!("loading outbound_allow_list");
                }
                "[black_list]" | "[bypass_list]" => {
                    curr = &mut bypass;
                    trace!("loading black_list / bypass_list");
                }
                "[white_list]" | "[proxy_list]" => {
                    curr = &mut proxy;
                    trace!("loading white_list / proxy_list");
                }
                _ => {
                    match line.parse::<IpNet>() {
                        Ok(IpNet::V4(v4)) => {
                            curr.add_ipv4_rule(v4);
                        }
                        Ok(IpNet::V6(v6)) => {
                            curr.add_ipv6_rule(v6);
                        }
                        Err(..) => {
                            // Maybe it is a pure IpAddr
                            match line.parse::<IpAddr>() {
                                Ok(IpAddr::V4(v4)) => {
                                    curr.add_ipv4_rule(v4);
                                }
                                Ok(IpAddr::V6(v6)) => {
                                    curr.add_ipv6_rule(v6);
                                }
                                Err(..) => {
                                    curr.add_regex_rule(line.to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            outbound_block: outbound_block.into_rules()?,
            outbound_allow: outbound_allow.into_rules()?,
            black_list: bypass.into_rules()?,
            white_list: proxy.into_rules()?,
            mode,
            outbound_mode,
            file_path,
        })
    }

    /// Get ACL file path
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Check if domain name is in proxy_list.
    /// If so, it should be resolved from remote (for Android's DNS relay)
    ///
    /// Return
    /// - `Some(true)` if `host` is in `white_list` (should be proxied)
    /// - `Some(false)` if `host` is in `black_list` (should be bypassed)
    /// - `None` if `host` doesn't match any rules
    pub fn check_host_in_proxy_list(&self, host: &str) -> Option<bool> {
        let host = Self::convert_to_ascii(host);
        self.check_ascii_host_in_proxy_list(&host)
    }

    /// Check if ASCII domain name is in proxy_list.
    /// If so, it should be resolved from remote (for Android's DNS relay)
    ///
    /// Return
    /// - `Some(true)` if `host` is in `white_list` (should be proxied)
    /// - `Some(false)` if `host` is in `black_list` (should be bypassed)
    /// - `None` if `host` doesn't match any rules
    pub fn check_ascii_host_in_proxy_list(&self, host: &str) -> Option<bool> {
        // Addresses in proxy_list will be proxied
        if self.white_list.check_host_matched(host) {
            return Some(true);
        }
        // Addresses in bypass_list will be bypassed
        if self.black_list.check_host_matched(host) {
            return Some(false);
        }
        None
    }

    /// If there are no IP rules
    #[inline]
    pub fn is_ip_empty(&self) -> bool {
        self.black_list.is_ip_empty() && self.white_list.is_ip_empty()
    }

    /// If there are no domain name rules
    #[inline]
    pub fn is_host_empty(&self) -> bool {
        self.black_list.is_host_empty() && self.white_list.is_host_empty()
    }

    /// Check if `IpAddr` should be proxied
    pub fn check_ip_in_proxy_list(&self, ip: &IpAddr) -> bool {
        if self.black_list.check_ip_matched(ip) {
            // If IP is in black_list, it should be bypassed
            return false;
        }
        if self.white_list.check_ip_matched(ip) {
            // If IP is in white_list, it should be proxied
            return true;
        }
        self.is_default_in_proxy_list()
    }

    /// Default mode
    ///
    /// Default behavior for hosts that are not configured
    /// - `true` - Proxied
    /// - `false` - Bypassed
    #[inline]
    pub fn is_default_in_proxy_list(&self) -> bool {
        match self.mode {
            Mode::BlackList => true,
            Mode::WhiteList => false,
        }
    }

    /// Returns the ASCII representation a domain name,
    /// if conversion fails returns original string
    fn convert_to_ascii(host: &str) -> Cow<'_, str> {
        idna::domain_to_ascii(host)
            .map(From::from)
            .unwrap_or_else(|_| host.into())
    }

    /// Check if target address should be bypassed (for client)
    ///
    /// This function may perform a DNS resolution
    pub async fn check_target_bypassed(&self, context: &Context, addr: &Address) -> bool {
        match *addr {
            Address::SocketAddress(ref addr) => !self.check_ip_in_proxy_list(&addr.ip()),
            // Resolve hostname and check the list
            Address::DomainNameAddress(ref host, port) => {
                if let Some(value) = self.check_host_in_proxy_list(host) {
                    return !value;
                }

                // If mode is BlackList, host is proxied by default. If it has any resolved IPs in black_list, then it should be bypassed.
                // If mode is WhiteList, host is bypassed by default. If it has any resolved IPs in white_list, then it should be proxied.
                let (check_list, bypass_if_matched) = match self.mode {
                    Mode::BlackList => (&self.black_list, true),
                    Mode::WhiteList => (&self.white_list, false),
                };

                if check_list.is_ip_empty() {
                    return !self.is_default_in_proxy_list();
                }

                if let Ok(vaddr) = context.dns_resolve(host, port).await {
                    for addr in vaddr {
                        let ip = addr.ip();
                        if check_list.check_ip_matched(&ip) {
                            return bypass_if_matched;
                        }
                    }
                }

                !self.is_default_in_proxy_list()
            }
        }
    }

    /// Check if client address should be blocked (for server)
    pub fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.mode {
            Mode::BlackList => {
                // Only clients in black_list will be blocked
                self.black_list.check_ip_matched(&addr.ip())
            }
            Mode::WhiteList => {
                // Only clients not in white_list will be blocked
                !self.white_list.check_ip_matched(&addr.ip())
            }
        }
    }

    /// Check if outbound address is blocked (for server)
    ///
    /// NOTE: `Address::DomainName` is only validated by regex rules,
    ///       resolved addresses are checked in the `lookup_outbound_then!` macro
    pub async fn check_outbound_blocked(&self, context: &Context, outbound: &Address) -> bool {
        match outbound {
            Address::SocketAddress(saddr) => self.check_outbound_ip_blocked(&saddr.ip()),
            Address::DomainNameAddress(host, port) => {
                let ascii_host = Self::convert_to_ascii(host);
                if self.outbound_block.check_host_matched(&ascii_host) {
                    return true; // Blocked by config
                }
                if self.outbound_allow.check_host_matched(&ascii_host) {
                    return false; // Allowed by config
                }

                // If no domain name rules matched,
                // we need to resolve the hostname to IP addresses

                // If mode is BlackList, host is allowed by default. If any of its' resolved IPs in outboud_block, then it is blocked.
                // If mode is WhiteList, host is blocked by default. If any of its' resolved IPs in outbound_allow, then it is allowed.
                let (check_rule, block_if_matched) = match self.outbound_mode {
                    Mode::BlackList => (&self.outbound_block, true),
                    Mode::WhiteList => (&self.outbound_allow, false),
                };

                if check_rule.is_ip_empty() {
                    // If there are no IP rules, use the default mode
                    return self.is_outbound_default_blocked();
                }

                if let Ok(vaddr) = context.dns_resolve(host, *port).await {
                    for addr in vaddr {
                        let ip = addr.ip();
                        if check_rule.check_ip_matched(&ip) {
                            return block_if_matched;
                        }
                    }
                }

                self.is_outbound_default_blocked()
            }
        }
    }

    fn check_outbound_ip_blocked(&self, ip: &IpAddr) -> bool {
        if self.outbound_block.check_ip_matched(ip) {
            // If IP is in outbound_block, it should be blocked
            return true;
        }
        if self.outbound_allow.check_ip_matched(ip) {
            // If IP is in outbound_allow, it should be allowed
            return false;
        }
        // If IP is not in any list, check the default mode
        self.is_outbound_default_blocked()
    }

    #[inline]
    fn is_outbound_default_blocked(&self) -> bool {
        match self.outbound_mode {
            Mode::BlackList => false,
            Mode::WhiteList => true,
        }
    }
}
