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

//! TcpRelay implementation

use std::net::SocketAddr;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::ops::Deref;

use crypto::cipher::{self, CipherType};
use crypto::CryptoMode;
use relay::socks5::Address;

use coio::net::TcpStream;

use self::stream::{DecryptedReader, EncryptedWriter};

mod cached_dns;
pub mod local;
pub mod server;
mod stream;
mod http;

#[derive(Clone)]
pub struct SharedTcpStream(Arc<TcpStream>);

impl SharedTcpStream {
    pub fn new(s: TcpStream) -> SharedTcpStream {
        SharedTcpStream(Arc::new(s))
    }
}

impl Read for SharedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for SharedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

impl Deref for SharedTcpStream {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        &*self.0
    }
}

fn connect_proxy_server(server_addr: &SocketAddr,
                        encrypt_method: CipherType,
                        pwd: &[u8],
                        relay_addr: &Address)
                        -> io::Result<(DecryptedReader<SharedTcpStream>, EncryptedWriter<SharedTcpStream>)> {
    let mut remote_stream = SharedTcpStream::new(try!(TcpStream::connect(&server_addr)));

    // Encrypt data to remote server

    // Send initialize vector to remote and create encryptor
    let mut encrypt_stream = {
        let local_iv = encrypt_method.gen_init_vec();
        trace!("Going to send initialize vector: {:?}", local_iv);
        let encryptor = cipher::with_type(encrypt_method, pwd, &local_iv[..], CryptoMode::Encrypt);
        if let Err(err) = remote_stream.write_all(&local_iv[..]) {
            error!("Error occurs while writing initialize vector: {}", err);
            return Err(err);
        }
        EncryptedWriter::new(remote_stream.clone(), encryptor)
    };

    trace!("Got encrypt stream and going to send addr: {:?}",
           relay_addr);

    // Send relay address to remote
    let mut addr_buf = Vec::new();
    try!(relay_addr.write_to(&mut addr_buf));
    if let Err(err) = encrypt_stream.write_all(&addr_buf).and_then(|_| encrypt_stream.flush()) {
        error!("Error occurs while writing address: {}", err);
        return Err(err);
    }

    // Decrypt data from remote server

    let remote_iv = {
        let mut iv = Vec::with_capacity(encrypt_method.block_size());
        unsafe {
            iv.set_len(encrypt_method.block_size());
        }

        let mut total_len = 0;
        while total_len < encrypt_method.block_size() {
            match remote_stream.read(&mut iv[total_len..]) {
                Ok(0) => {
                    error!("Unexpected EOF while reading initialize vector");
                    debug!("Already read: {:?}", &iv[..total_len]);

                    let err = io::Error::new(io::ErrorKind::UnexpectedEof,
                                             "Unexpected EOF while reading initialize vector");
                    return Err(err);
                }
                Ok(n) => total_len += n,
                Err(err) => {
                    error!("Error while reading initialize vector: {}", err);
                    return Err(err);
                }
            }
        }
        iv
    };

    trace!("Got initialize vector {:?}", remote_iv);

    let decryptor = cipher::with_type(encrypt_method, pwd, &remote_iv[..], CryptoMode::Decrypt);
    let decrypt_stream = DecryptedReader::new(remote_stream, decryptor);

    trace!("Finished creating remote encrypt stream pair");
    Ok((decrypt_stream, encrypt_stream))
}

#[cfg(debug_assertions)]
mod stat {
    use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

    static GLOBAL_TCP_WORK_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;
    static GLOBAL_HTTP_WORK_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

    pub fn global_tcp_work_count_add() {
        GLOBAL_TCP_WORK_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    pub fn global_tcp_work_count_sub() {
        GLOBAL_TCP_WORK_COUNT.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn global_tcp_work_count_get() -> usize {
        GLOBAL_TCP_WORK_COUNT.load(Ordering::Relaxed)
    }

    pub fn global_http_work_count_add() {
        GLOBAL_HTTP_WORK_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    pub fn global_http_work_count_sub() {
        GLOBAL_HTTP_WORK_COUNT.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn global_http_work_count_get() -> usize {
        GLOBAL_HTTP_WORK_COUNT.load(Ordering::Relaxed)
    }
}

#[cfg(not(debug_assertions))]
mod stat {
    pub fn global_tcp_work_count_add() {}
    pub fn global_tcp_work_count_sub() {}

    pub fn global_tcp_work_count_get() -> usize {
        0
    }

    pub fn global_http_work_count_add() {}
    pub fn global_http_work_count_sub() {}

    pub fn global_http_work_count_get() -> usize {
        0
    }
}

struct TcpWorkCounter;

impl TcpWorkCounter {
    fn new() -> TcpWorkCounter {
        stat::global_tcp_work_count_add();
        TcpWorkCounter
    }
}

impl Drop for TcpWorkCounter {
    fn drop(&mut self) {
        stat::global_tcp_work_count_sub();
    }
}

struct HttpWorkCounter;

impl HttpWorkCounter {
    fn new() -> HttpWorkCounter {
        stat::global_http_work_count_add();
        HttpWorkCounter
    }
}

impl Drop for HttpWorkCounter {
    fn drop(&mut self) {
        stat::global_http_work_count_sub();
    }
}

/// Get total TCP relay work count
pub fn global_tcp_work_count() -> usize {
    stat::global_tcp_work_count_get()
}

/// Get total HTTP relay work count
pub fn global_http_work_count() -> usize {
    stat::global_http_work_count_get()
}
