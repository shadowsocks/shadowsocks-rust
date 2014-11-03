// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

#[phase(plugin, link)]
extern crate log;

extern crate native;

use std::io::{IoResult, TcpStream};

use relay::socks5::SOCKS5_VERSION;

mod cached_dns;
pub mod local;
pub mod server;

pub fn send_error_reply(stream: &mut Writer, err_code: u8) -> IoResult<()> {
    let reply = [SOCKS5_VERSION, err_code, 0x00];
    try!(stream.write(reply));
    try!(stream.flush());
    Ok(())
}

pub fn relay_and_map(from: &mut Reader, to: &mut Writer, mapper: |&[u8]| -> Vec<u8>)
        -> IoResult<()> {
    let mut buf = [0u8, .. 0xffff];
    loop {
        let len = try!(from.read(buf));
        let msg = mapper(buf.slice_to(len));
        try!(to.write(msg.as_slice()));
        try!(to.flush());
    }
}
