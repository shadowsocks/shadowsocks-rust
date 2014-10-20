# shadowsocks-rust

This is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you bypass firewalls.

*Currently developing and testing with rust-0.12-dev*

## Dependences

* libcrypto (OpenSSL)
* Rust >= 0.12
* Cargo

## Usage

Build with [Cargo](http://doc.crates.io):

```bash
cargo build
```

Then `sslocal` and `ssserver` will appear in `./target`, it works similarly as the two binaries of
the official shadowsocks' implementation.

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
    "method": "aes-256-cfb",
    "fast_open": false,
    "workers": 1
}
```

Detailed explaination could be found in [shadowsocks' documentation](https://github.com/clowwindy/shadowsocks/wiki).

Start local and server shadowsocks with

```
sslocal -c config.json
ssserver -c config.json
```

List all available arguments with `-h`.

## Notes

Still under developing and waiting for the final release of rust-1.0.

Currently implementation can only be built by rust-0.12-dev. It supports the following features:

* CONNECT command
* AES-(128|192|256)-CFB crypto algorithm

## TODO

* Documentation
* UDP_ASSOCIATION command
* BIND command
* Sock5 authentication
* Extend configuration format
* Fully testing on server
* Multiple worker
* User management
