FROM --platform=$BUILDPLATFORM rust:1.53.0-buster AS build

ARG TARGETARCH

RUN apt-get update && apt-get install -y build-essential curl musl-tools

WORKDIR /root/shadowsocks-rust

ADD . .

RUN rustup install nightly && \
    case "$TARGETARCH" in \
    "386") \
        RUST_TARGET="i686-unknown-linux-musl" \
        MUSL="i686-linux-musl" \
        ;; \
    "amd64") \
        RUST_TARGET="x86_64-unknown-linux-musl" \
        MUSL="x86_64-linux-musl" \
        ;; \
    "arm64") \
        RUST_TARGET="aarch64-unknown-linux-musl" \
        MUSL="aarch64-linux-musl" \
        ;; \
    *) \
        echo "Doesn't support $TARGETARCH architecture" \
        exit 1 \
        ;; \
    esac && \
    wget -qO- "https://musl.cc/$MUSL-cross.tgz" | tar -xzC /root/ && \
    CC=/root/$MUSL-cross/bin/$MUSL-gcc && \
    rustup target add $RUST_TARGET && \
    RUSTFLAGS="-C linker=$CC" CC=$CC cargo build --target "$RUST_TARGET" --release --features "local-tun local-redir armv8 neon" && \
    mv target/$RUST_TARGET/release/ss* target/release/

FROM alpine:3.14 AS sslocal

COPY --from=build /root/shadowsocks-rust/target/release/sslocal /usr/bin

COPY --from=build /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/

USER nobody

ENTRYPOINT [ "sslocal", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]

FROM alpine:3.14 AS ssserver

COPY --from=build /root/shadowsocks-rust/target/release/ssserver /usr/bin

COPY --from=build /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/

USER nobody

ENTRYPOINT [ "ssserver", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]
