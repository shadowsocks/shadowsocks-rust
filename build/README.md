## Build Standalone Binaries

### Build Docker Image

```bash
docker build -t shadowsocks-rust:x86_64-unknown-linux-musl -f Dockerfile.x86_64-unknown-linux-musl .
```

### Build Binaries

- Install [`cross`](https://github.com/rust-embedded/cross)

```bash
cargo install cross
```

- Build with cross

```bash
cross build --target x86_64-unknown-linux-musl
```