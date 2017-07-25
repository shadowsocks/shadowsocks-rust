Compile static-linked binaries with [`rust-musl-builder`](https://github.com/emk/rust-musl-builder):

```sh
# build image use Dockerfile in build dir.
docker build -t shadowsocks_rust:0.0.1 .
# run command in project root.
alias rust-musl-builder='docker run --rm -it -v "$(pwd)":/home/rust/src shadowsocks_rust:0.0.1'
rust-musl-builder cargo build --release
```

At the moment, it doesn't attempt to cache libraries between builds, so this is best reserved for making final release builds.