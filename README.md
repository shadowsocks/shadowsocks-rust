# shadowsocks-rust

[![Build Status](https://img.shields.io/travis/zonyitoo/shadowsocks-rust.svg)](https://travis-ci.org/zonyitoo/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/qx3wfyjxxuokvyrs?svg=true)](https://ci.appveyor.com/project/zonyitoo/shadowsocks-rust)
[![License](https://img.shields.io/github/license/zonyitoo/shadowsocks-rust.svg)](https://github.com/zonyitoo/shadowsocks-rust)

This is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you <del>bypass firewalls</del>.

> **THIS PROJECT IS <u>ONLY FOR</u> TESTING THE AVAILABILITY AND USABILITY OF MY COROUTINE SERVER PROJECT.**

> **IF YOU ARE INTERESTED, PLEASE REFER TO `coio-rs` and `simplesched` PROJECT**.

It is **unstable**! If you encounter any problems, please open an issue.

## Dependencies

* libcrypto (OpenSSL)
* Rust nightly
* Cargo

## Usage

Build with [Cargo](http://doc.crates.io):

```bash
cargo build
```

Then `sslocal` and `ssserver` will appear in `./target`, it works similarly as the two binaries of
the official shadowsocks' implementation.

Enable more crypto algorithms by passing the name `cipher-[name]` via command line argument `--features`

```bash
cargo build --features "cipher-aes-ctr"
```

Read `Cargo.toml` for more details.

*Require `libcrypto` by default.*

## Getting Started

Create a shadowsocks' configuration file. Example

```json
{
    "server": "my_server_ip",
    "server_port": 8388,
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "mypassword",
    "timeout": 300,
    "method": "aes-256-cfb"
}
```

Detailed explaination could be found in [shadowsocks' documentation](https://github.com/clowwindy/shadowsocks/wiki).

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
    "local_address": "127.0.0.1"
}
```

The `sslocal` will use a load balancing algorithm to dispatch packages to all servers.

Start local and server shadowsocks with

```
cargo run --bin sslocal -- -c config.json
cargo run --bin ssserver -- -c config.json
```

List all available arguments with `-h`.

## Useful Tools

1. `socks5-tool` is to demonstrate how to write a Socks5 client.

2. `ssurl` is for encoding and decoding ShadowSocks URLs. Example: `ss://YWVzLTI1Ni1jZmI6aGVsbG93b3JsZF9mdWNrQDEyNy4wLjAuMTo4Mzg4`

## Notes

It supports the following features:

* CONNECT, UDP ASSOCIATE commands
* Crypto algorithms defined in `Cargo.toml`
* **Load balancing**

Currently it uses [coio-rs](https://github.com/zonyitoo/coio-rs) as the backend support library and it does not support Windows, <del>LoL</del>.

## TODO

- [ ] Documentation
- [ ] <del>`BIND` command</del>
- [ ] Socks5 authentication
- [x] Extend configuration format
- [ ] Fully testing on servers
- [ ] Performance testing and improvement
- [ ] User management
- [ ] <del>PAC</del>
- [x] Improved logging format (waiting for the new official log crate)
- [ ] Support more ciphers without depending on `libcrypto` (waiting for an acceptable Rust crypto lib implementation)
- [ ] Windows support. Depending on Mio and Coio-rs.
- [ ] Build with stable.

## License

[The MIT License (MIT)](http://opensource.org/licenses/MIT)

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
