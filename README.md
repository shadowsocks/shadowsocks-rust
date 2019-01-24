# shadowsocks-rust

[![Build Status](https://img.shields.io/travis/shadowsocks/shadowsocks-rust.svg)](https://travis-ci.org/shadowsocks/shadowsocks-rust)
[![License](https://img.shields.io/github/license/zonyitoo/shadowsocks-rust.svg)](https://github.com/zonyitoo/shadowsocks-rust)
[![crates.io](https://img.shields.io/crates/v/shadowsocks-rust.svg)](https://crates.io/crates/shadowsocks-rust)
[![Release](https://img.shields.io/github/release/shadowsocks/shadowsocks-rust.svg)](https://github.com/shadowsocks/shadowsocks-rust/releases)

This is a port of [shadowsocks](https://github.com/shadowsocks/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you <del>bypass firewalls</del>.

## Dependencies

* libcrypto (OpenSSL)
* libsodium >= 1.0.7 (Required for ciphers that are provided by libsodium)

## Build & Install

### **crates.io**

Install from [crates.io](https://crates.io/crates/shadowsocks-rust):

```bash
cargo install shadowsocks-rust
```

then you can find `sslocal` and `ssserver` in `$CARGO_HOME/bin`.

### **Download release**

Requirements:

* Linux x86\_64

Download static-linked build [here](https://github.com/shadowsocks/shadowsocks-rust/releases).

### **Build from source**

Use cargo to build.

```bash
cargo build --release
```

NOTE: If you haven't installed the correct version of `libsodium` in your system, you can set a environment variable `SODIUM_BUILD_STATIC=yes` to let `libsodium-ffi` to build `libsodium` from source, which requires you to have build tools (including GCC, libtools, etc.) installed.

```bash
SODIUM_BUILD_STATIC=yes cargo build --release
```

Then `sslocal` and `ssserver` will appear in `./target/(debug|release)/`, it works similarly as the two binaries in the official ShadowSocks' implementation.

```bash
make install TARGET=release
```

Then `sslocal`, `ssserver` and `ssurl` will be installed in `/usr/local/bin` (variable PREFIX).

For Windows users, if you have encountered any problem in building, check and discuss in [#102](https://github.com/shadowsocks/shadowsocks-rust/issues/102).

### **Build standalone binaries**

Requirements:

* Docker

```bash
./build/build-release
```

Then `sslocal`, `ssserver` and `ssurl` will be packaged in

- `./build/shadowsocks-latest-release.x86_64-unknown-linux-musl.tar.gz`
- `./build/shadowsocks-latest-release.x86_64-unknown-linux-musl.tar.xz`

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
    "method": "aes-256-cfb"
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
            "timeout": 300
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

Start local and server ShadowSocks with
If you Build it with Makefile:

```bash
$ sslocal -c config.json
$ ssserver -c config.json
```

If you Build it with Cargo:

```bash
$ cargo run --bin sslocal -- -c config.json
$ cargo run --bin ssserver -- -c config.json
```

List all available arguments with `-h`.

## Usage

Local client

```bash
# Read local client configuration from file
$ sslocal -c /path/to/shadowsocks.json

# Pass all parameters via command line
$ sslocal -b "127.0.0.1:1080" -s "[::1]:8388" -m "aes-256-gcm" -k "hello-kitty" --plugin "obfs-local" --plugin-opts "obfs=tls"

# Pass server with SIP002 URL
$ sslocal -b "127.0.0.1:1080" --server-url "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dtls"
```

Server

```bash
# Read server configuration from file
$ ssserver -c /path/to/shadowsocks.json

# Pass all parameters via command line
$ ssserver -s "[::]:8388" -m "aes-256-gcm" -k "hello-kitty" --plugin "obfs-server" --plugin-opts "obfs=tls"
```

DNS Local server

```bash
# Read configuration from file
$ ssdns -c /path/to/shadowsocks.json

# Pass all parameters via command line
$ ssdns -s "[::]:8388" -m "aes-256-gcm" -k "hello-kitty" --dns "8.8.8.8:53"
```

For DNS relay server, you can set remote DNS server in configuration file with `dns` key in root object.

```json
{
    "dns": "8.8.8.8"
}
```

## Supported Ciphers

### Stream Ciphers

* `aes-128-cfb`, `aes-128-cfb1`, `aes-128-cfb8`, `aes-128-cfb128`
* `aes-256-cfb`, `aes-256-cfb1`, `aes-256-cfb8`, `aes-256-cfb128`
* `rc4`, `rc4-md5`
* `chacha20`, `salsa20`, `chacha20-ietf`
* `plain` (No encryption, just for debugging)

### AEAD Ciphers

* `aes-128-gcm`, `aes-256-gcm`
* `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`
* `aes-128-pmac-siv`, `aes-256-pmac-siv` (experimental)

## Useful Tools

1. `ssurl` is for encoding and decoding ShadowSocks URLs (SIP002). Example:

    ```plain
    ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.baidu.com
    ```

## Notes

It supports the following features:

- [x] Socks5 CONNECT command
- [x] UDP ASSOCIATE command (partial)
- [ ] <del>HTTP Proxy protocol</del> Deprecated, use `privoxy` instead.
- [x] Various crypto algorithms
- [x] Load balancing (multiple servers)
- [x] [SIP004](https://github.com/shadowsocks/shadowsocks-org/issues/30) AEAD ciphers
- [x] [SIP003](https://github.com/shadowsocks/shadowsocks-org/issues/28) Plugins
- [x] [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) Extension ss URLs

## TODO

- [x] Documentation
- [x] Extend configuration format
- [x] Improved logging format (waiting for the new official log crate)
- [ ] Support more ciphers without depending on `libcrypto` (waiting for an acceptable Rust crypto lib implementation)
- [x] Windows support. <del>(Depending on mio and coio-rs)</del>
- [x] Build with stable. <del>(Depending on coio)</del>
- [ ] <del>Support HTTP Proxy protocol</del> (it is easy to use another tools to convert HTTP proxy protocol to Socks5, like `privoxy`)
- [ ] <del>One-time Auth.</del> (Already deprecated according to Shadowsocks' community)
- [x] AEAD ciphers. (proposed in [SIP004](https://github.com/shadowsocks/shadowsocks-org/issues/30), still under discussion)


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
