# shadowsocks-rust

This is a port of [shadowsocks](https://github.com/clowwindy/shadowsocks).

shadowsocks is a fast tunnel proxy that helps you bypass firewalls.

*Currently developing and testing with rust-0.12-dev*

## Usage

Build with [Cargo](http://doc.crates.io):

```bash
cargo build
```

Then `sslocal` and `ssserver` will appear in `./target`, it works similarly as the two binaries of
the official shadowsocks' implementation.

```
Usage: ./target/sslocal [options]

Options:
    -v --version        print version
    -h --help           print this message
    -c --config config.json
                        specify config file
    -s --server-addr    server address
    -b --local-addr     local address, listen only to this address if
                        specified
    -k --password       password
    -p --server-port    server port
    -l --local-port     local socks5 proxy port
    -m --encrypt-method aes-128-cfb
                        entryption method
```

```
Usage: ./target/ssserver [options]

Options:
    -v --version        print version
    -h --help           print this message
    -c --config config.json
                        specify config file
    -s --server-addr    server address
    -b --local-addr     local address, listen only to this address if
                        specified
    -k --password       password
    -p --server-port    server port
    -l --local-port     local socks5 proxy port
    -m --encrypt-method aes-128-cfb
                        entryption method
```

## Notes

Still under developing and waiting for the final release of rust-1.0.

Currently implementation can only be built by rust-0.12-dev. It supports the following features:

* CONNECT command
* AES-(128|256|512)-CFB crypto algorithm
