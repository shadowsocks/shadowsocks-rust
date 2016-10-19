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

fn connect_proxy_server(server_addr: &SocketAddr,
                        encrypt_method: CipherType,
                        pwd: &[u8],
                        relay_addr: &Address)
                        -> io::Result<(DecryptedReader<TcpStream>, EncryptedWriter<TcpStream>)> {
    let mut remote_stream = try!(TcpStream::connect(&server_addr));

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

        let remote_writer = match remote_stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                error!("Error occurs while cloning remote stream: {}", err);
                return Err(err);
            }
        };
        EncryptedWriter::new(remote_writer, encryptor)
    };

    trace!("Got encrypt stream and going to send addr: {:?}", relay_addr);

    // Send relay address to remote
    let mut addr_buf = Vec::new();
    relay_addr.write_to(&mut addr_buf).unwrap();
    if let Err(err) = encrypt_stream.write_all(&addr_buf) {
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
