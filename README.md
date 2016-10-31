# shadowsocks-rust

[![Build Status](https://img.shields.io/travis/zonyitoo/shadowsocks-rust.svg)](https://travis-ci.org/zonyitoo/shadowsocks-rust)
[![License](https://img.shields.io/github/license/zonyitoo/shadowsocks-rust.svg)](https://github.com/zonyitoo/shadowsocks-rust)

This is a port of [shadowsocks](https://github.com/shadowsocks/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you <del>bypass firewalls</del>.

It is **unstable**! If you encounter any problems, please open an issue.

## Dependencies

* libcrypto (OpenSSL)
* <del>libsodium</del>

## Usage

Build with [Cargo](http://doc.crates.io):

```bash
cargo build
```

Then `sslocal` and `ssserver` will appear in `./target`, it works similarly as the two binaries in
the official ShadowSocks' implementation.

Enable more crypto algorithms by passing the name `cipher-[name]` via command line argument `--features`

```bash
cargo build --features "cipher-aes-ctr"
```

Read `Cargo.toml` for more details.

## Getting Started

Create a ShadowSocks' configuration file. Example

```json
{
    "server": "my_server_ip",
    "server_port": 8388,
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "mypassword",
    "timeout": 300,
    "method": "aes-256-cfb",

    "local_http_port": 10240,
    "local_http_address": "127.0.0.1"
}
```

Detailed explaination could be found in [shadowsocks' documentation](https://github.com/shadowsocks/shadowsocks/wiki).

In shadowsocks-rust, we also have an extended configuration file format, which is able to define more than one servers:

```json
{
    "servers": [
        {
            "address": "127.0.0.1",
            "port": 1080,
            "password": "hello-world",
            "method": "bf-cfb",
            "timeout": 300,
        },
        {
            "address": "127.0.0.1",
            "port": 1081,
            "password": "hello-kitty",
            "method": "aes-128-cfb"
        }
    ],
    "local_port": 8388,
    "local_address": "127.0.0.1",

    "local_http_port": 10240,
    "local_http_address": "127.0.0.1"
}
```

The `sslocal` will use a load balancing algorithm to dispatch packages to all servers.

Start local and server ShadowSocks with

```
cargo run --bin sslocal -- -c config.json
cargo run --bin ssserver -- -c config.json
```

List all available arguments with `-h`.

## Useful Tools

1. `ssurl` is for encoding and decoding ShadowSocks URLs. Example: `ss://YWVzLTI1Ni1jZmI6aGVsbG93b3JsZF9mdWNrQDEyNy4wLjAuMTo4Mzg4`

## Notes

It supports the following features:

- [x] Socks5 CONNECT command
- [x] UDP ASSOCIATE command (partial)
- [x] HTTP Proxy protocol
- [x] Various crypto algorithms
- [x] Load balancing (multiple servers)

## TODO

- [x] Documentation
- [x] Extend configuration format
- [x] Improved logging format (waiting for the new official log crate)
- [ ] Support more ciphers without depending on `libcrypto` (waiting for an acceptable Rust crypto lib implementation)
- [x] Windows support. <del>(Depending on mio and coio-rs)</del>
- [x] Build with stable. <del>(Depending on coio)</del>
- [x] Support HTTP Proxy protocol

## License

[The MIT License (MIT)](https://opensource.org/licenses/MIT)

Copyright (c) 2014 Y. T. CHUNG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
