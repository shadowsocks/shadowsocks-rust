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

#![unstable(reason = "Waiting for Rust 1.0.0 final release")]
#![crate_type = "lib"]
#![crate_name = "shadowsocks"]

#![feature(unsafe_destructor, box_syntax, libc, core, io, old_path, net, fs, std_misc, collections, test)]

extern crate "rustc-serialize" as serialize;
#[macro_use]
extern crate log;
extern crate "lru-cache" as lru_cache;

extern crate "libsodium-sys" as libsodium_ffi;

extern crate byteorder;
extern crate rand;
extern crate getopts;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub mod config;
pub mod relay;
pub mod crypto;
