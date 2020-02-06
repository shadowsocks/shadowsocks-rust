# shadowsocks-rust

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2029e102e1bd46fb9423cb35980636b7)](https://app.codacy.com/app/zonyitoo/shadowsocks-rust?utm_source=github.com&utm_medium=referral&utm_content=shadowsocks/shadowsocks-rust&utm_campaign=Badge_Grade_Dashboard)
[![Build Status](https://img.shields.io/travis/shadowsocks/shadowsocks-rust.svg)](https://travis-ci.org/shadowsocks/shadowsocks-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/h3ny0dov7v9xioa5?svg=true)](https://ci.appveyor.com/project/zonyitoo/shadowsocks-rust-0grjf)
[![License](https://img.shields.io/github/license/zonyitoo/shadowsocks-rust.svg)](https://github.com/zonyitoo/shadowsocks-rust)
[![crates.io](https://img.shields.io/crates/v/shadowsocks-rust.svg)](https://crates.io/crates/shadowsocks-rust)
[![dependency status](https://deps.rs/repo/github/shadowsocks/shadowsocks-rust/status.svg)](https://deps.rs/repo/github/shadowsocks/shadowsocks-rust)
[![Release](https://img.shields.io/github/release/shadowsocks/shadowsocks-rust.svg)](https://github.com/shadowsocks/shadowsocks-rust/releases)
[![CircleCI](https://circleci.com/gh/shadowsocks/shadowsocks-rust.svg?style=svg)](https://circleci.com/gh/shadowsocks/shadowsocks-rust)

This is a port of [shadowsocks](https://github.com/shadowsocks/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you bypass firewalls.

## Dependencies

* libcrypto (OpenSSL) (Required for `aes-*`, `camellia-*` and `rc4` ciphers)
* libsodium >= 1.0.7 (Required for ciphers that are provided by libsodium)

## Build & Install

### Optional Features

* `sodium` - Enabled linking to [`libsodium`](https://github.com/jedisct1/libsodium), which will also enable ciphers that depending on `libsodium`.

* `rc4` - Enabled `rc4` encryption algorithm. Some OpenSSL Crypto does not ship with `rc4`, because it was already deprecated in 2015.

* `aes-cfb` - Enabled `aes-*-cfb` encryption algorithm.

* `aes-ctr` - Enabled `aes-*-ctr` encryption algorithm.

* `camellia-cfb` - Enabled `camellia-*-cfb` encryption algorithm.

* `single-threaded` - Let `sslocal` and `ssserver` run in single threaded mode (by using Tokio's `basic_scheduler`).

* `trust-dns` - Uses [`trust-dns-resolver`](https://crates.io/crates/trust-dns-resolver) as DNS resolver instead of `tokio`'s builtin.

Default features: `["sodium", "rc4", "aes-cfb", "aes-ctr", "trust-dns"]`.

NOTE: To disable dependency of OpenSSL, just disable feature `rc4`, `aes-cfb`, `aes-ctr`, `camellia-cfb`.

### **crates.io**

Install from [crates.io](https://crates.io/crates/shadowsocks-rust):

```bash
cargo install shadowsocks-rust
```

then you can find `sslocal` and `ssserver` in `$CARGO_HOME/bin`.

### **Download release**

Requirements:

* Linux x86\_64
* Windows x86\_64

Download static-linked build [here](https://github.com/shadowsocks/shadowsocks-rust/releases).

Nightly builds could be downloaded from [CircleCI](https://circleci.com/gh/shadowsocks/shadowsocks-rust).

* `build-windows`: Build for `x86_64-pc-windows-msvc`
* `build-linux`: Build for `x86_64-unknown-linux-gnu`, Debian 9 (Stretch)
* `build-docker`: Build for `x86_64-unknown-linux-musl`, `x86_64-pc-windows-gnu`

### **Build from source**

Use cargo to build.

```bash
cargo build --release
```

NOTE: [`libsodium-sys`](https://crates.io/crates/libsodium-sys) builds and links statically to the `libsodium` in its package. Here are some useful environment variables for customizing build processes:

* Find `libsodium` installed in customized path:

  * `SODIUM_LIB_DIR` - Directory path to `libsodium.a` or `sodium.lib`
  * `SODIUM_SHARED` - Dynamic-link instead of default static-link

* Find `libsodium` with `pkg-config` (*nix), `vcpkg` (MSVC)

  * `SODIUM_USE_PKG_CONFIG=1`

```bash
SODIUM_USE_PKG_CONFIG=1 cargo build --release
```

Then `sslocal` and `ssserver` will appear in `./target/(debug|release)/`, it works similarly as the two binaries in the official ShadowSocks' implementation.

```bash
make install TARGET=release
```

Then `sslocal`, `ssserver`, `sstunnel` and `ssurl` will be installed in `/usr/local/bin` (variable PREFIX).

For Windows users, if you have encountered any problem in building, check and discuss in [#102](https://github.com/shadowsocks/shadowsocks-rust/issues/102).

### **Build standalone binaries**

Requirements:

* Docker

```bash
./build/build-release
```

Then `sslocal`, `ssserver`, `sstunnel` and `ssurl` will be packaged in

* `./build/shadowsocks-${VERSION}-stable.x86_64-unknown-linux-musl.tar.xz`
* `./build/shadowsocks-${VERSION}-stable.x86_64-pc-windows-gnu.zip`

Read `Cargo.toml` for more details.

### Build OpenSSL from source

Specify feature `openssl-vendored` to let [openssl](https://crates.io/crates/openssl) build from source.

```bash
cargo build --features "openssl-vendored"
```

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

Detailed explanation could be found in [shadowsocks' documentation](https://github.com/shadowsocks/shadowsocks/wiki).

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
sslocal -c config.json
ssserver -c config.json
```

If you Build it with Cargo:

```bash
cargo run --bin sslocal -- -c config.json
cargo run --bin ssserver -- -c config.json
```

List all available arguments with `-h`.

## Usage

### Socks5 Local client

```bash
# Read local client configuration from file
sslocal -c /path/to/shadowsocks.json

# Pass all parameters via command line
sslocal -b "127.0.0.1:1080" -s "[::1]:8388" -m "aes-256-gcm" -k "hello-kitty" --plugin "obfs-local" --plugin-opts "obfs=tls"

# Pass server with SIP002 URL
sslocal -b "127.0.0.1:1080" --server-url "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dtls"
```

### HTTP Local client

```bash
# Read local client configuration from file
sslocal -c /path/to/shadowsocks.json --protocol http
```

All parameters are the same as Socks5 client, except `--protocol http`.

### Tunnel Local client

```bash
# Read local client configuration from file
# Set 127.0.0.1:8080 as the target for forwarding to
sstunnel -c /path/to/shadowsocks.json -f "127.0.0.1:8080"
```

`sstunnel` basically works the same as `sslocal`, only it doesn't have any client negociation process, just establishes a tunnel to the `forward` address.

### Server

```bash
# Read server configuration from file
ssserver -c /path/to/shadowsocks.json

# Pass all parameters via command line
ssserver -s "[::]:8388" -m "aes-256-gcm" -k "hello-kitty" --plugin "obfs-server" --plugin-opts "obfs=tls"
```

## Supported Ciphers

### Stream Ciphers

* `aes-128-cfb`, `aes-128-cfb1`, `aes-128-cfb8`, `aes-128-cfb128`
* `aes-192-cfb`, `aes-192-cfb1`, `aes-192-cfb8`, `aes-192-cfb128`
* `aes-256-cfb`, `aes-256-cfb1`, `aes-256-cfb8`, `aes-256-cfb128`
* `aes-128-ctr`
* `aes-192-ctr`
* `aes-256-ctr`
* `camellia-128-cfb`, `camellia-128-cfb1`, `camellia-128-cfb8`, `camellia-128-cfb128`
* `camellia-192-cfb`, `camellia-192-cfb1`, `camellia-192-cfb8`, `camellia-192-cfb128`
* `camellia-256-cfb`, `camellia-256-cfb1`, `camellia-256-cfb8`, `camellia-256-cfb128`
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

* [x] Socks5 CONNECT command
* [x] Socks5 UDP ASSOCIATE command (partial)
* [x] Various crypto algorithms
* [x] Load balancing (multiple servers) and server delay checking
* [x] [SIP004](https://github.com/shadowsocks/shadowsocks-org/issues/30) AEAD ciphers
* [x] [SIP003](https://github.com/shadowsocks/shadowsocks-org/issues/28) Plugins
* [x] [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) Extension ss URLs
* [x] HTTP Proxy Supports ([RFC 7230](http://tools.ietf.org/html/rfc7230) and [CONNECT](https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01))
* [x] Defend against replay attacks, [shadowsocks/shadowsocks-org#44](https://github.com/shadowsocks/shadowsocks-org/issues/44)

## TODO

* [x] Documentation
* [x] Extend configuration format
* [x] Improved logging format (waiting for the new official log crate)
* [ ] Support more ciphers without depending on `libcrypto` (waiting for an acceptable Rust crypto lib implementation)
* [x] Windows support.
* [x] Build with stable `rustc`.
* [x] Support HTTP Proxy protocol
* [ ] One-time Auth. (Already deprecated according to Shadowsocks' community)
* [x] AEAD ciphers. (proposed in [SIP004](https://github.com/shadowsocks/shadowsocks-org/issues/30), still under discussion)
* [x] Choose server based on delay #152
* [ ] Support TCP Fast Open

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
