FROM --platform=$BUILDPLATFORM rust:alpine3.20 AS builder

ARG TARGETARCH

RUN set -x \
    && apk add --no-cache build-base cmake llvm15-dev clang15-libclang clang15 rust-bindgen

WORKDIR /root/shadowsocks-rust

ADD . .

RUN case "$TARGETARCH" in \
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
    esac \
    && wget -qO- "https://musl.cc/$MUSL-cross.tgz" | tar -xzC /root/ \
    && PATH="/root/$MUSL-cross/bin:$PATH" \
    && CC=/root/$MUSL-cross/bin/$MUSL-gcc \
    && echo "CC=$CC" \
    && rustup override set stable \
    && rustup target add "$RUST_TARGET" \
    && RUSTFLAGS="-C linker=$CC" CC=$CC cargo build --target "$RUST_TARGET" --release --features "full" \
    && mv target/$RUST_TARGET/release/ss* target/release/

FROM alpine:3.21 AS sslocal

# NOTE: Please be careful to change the path of these binaries, refer to #1149 for more information.
COPY --from=builder /root/shadowsocks-rust/target/release/sslocal /usr/bin/
COPY --from=builder /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/
COPY --from=builder /root/shadowsocks-rust/docker/docker-entrypoint.sh /usr/bin/

ENTRYPOINT [ "docker-entrypoint.sh" ]
CMD [ "sslocal", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]

FROM alpine:3.21 AS ssserver

COPY --from=builder /root/shadowsocks-rust/target/release/ssserver /usr/bin/
COPY --from=builder /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/
COPY --from=builder /root/shadowsocks-rust/docker/docker-entrypoint.sh /usr/bin/

ENTRYPOINT [ "docker-entrypoint.sh" ]

CMD [ "ssserver", "--log-without-time", "-a", "nobody", "-c", "/etc/shadowsocks-rust/config.json" ]