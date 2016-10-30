// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! UDP relay proxy server

use std::rc::Rc;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor};
use std::cell::RefCell;
use std::mem;

use futures::{self, Future, Poll, Async};
use futures::stream::Stream;

use tokio_core::reactor::Handle;
use tokio_core::net::UdpSocket;

use lru_cache::LruCache;

use ip::IpAddr;

use config::{Config, ServerConfig, ServerAddr};
use relay::{BoxIoFuture, boxed_future};
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};
use relay::dns_resolver::DnsResolver;
use relay::socks5::{Address, UdpAssociateHeader};
use crypto::cipher::{self, Cipher};
use crypto::CryptoMode;

use super::MAXIMUM_ASSOCIATE_MAP_SIZE;

type AssociateMap = LruCache<Address, SocketAddr>;
type ServerCache = LruCache<SocketAddr, Rc<ServerConfig>>;

/// UDP relay proxy server
pub struct UdpRelayServer;