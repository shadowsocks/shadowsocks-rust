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
        SHA512="5047afc68170a2910895db2dfa448227e71a984bfa2130a1bc946fd1015d722b80b15e4abf90c64300815aa84fe781cc8b8a72f10174f9dce96169e035911880" \
    ;; \
    "amd64") \
        RUST_TARGET="x86_64-unknown-linux-musl" \
        MUSL="x86_64-linux-musl" \
        SHA512="52abd1a56e670952116e35d1a62e048a9b6160471d988e16fa0e1611923dd108a581d2e00874af5eb04e4968b1ba32e0eb449a1f15c3e4d5240ebe09caf5a9f3" \
    ;; \
    "arm64") \
        RUST_TARGET="aarch64-unknown-linux-musl" \
        MUSL="aarch64-linux-musl" \
        SHA512="8695ff86979cdf30fbbcd33061711f5b1ebc3c48a87822b9ca56cde6d3a22abd4dab30fdcd1789ac27c6febbaeb9e5bde59d79d66552fae53d54cc1377a19272" \
    ;; \
    *) \
        echo "Doesn't support $TARGETARCH architecture" \
        exit 1 \
    ;; \
    esac \
    && wget "https://github.com/AaronChen0/musl-cc-mirror/releases/download/2021-09-23/$MUSL-cross.tgz" \
    && ( echo "$SHA512" "$MUSL-cross.tgz" | sha512sum -c ) \
    && tar -xzf "$MUSL-cross.tgz" -C /root/ \
    && PATH="/root/$MUSL-cross/bin:$PATH" \
    && CC=/root/$MUSL-cross/bin/$MUSL-gcc \
    && echo "CC=$CC" \
    && rustup override set stable \
    && rustup target add "$RUST_TARGET" \
    && RUSTFLAGS="-C linker=$CC" CC=$CC cargo build --target "$RUST_TARGET" --release --features "full" \
    && mv target/$RUST_TARGET/release/ss* target/release/

FROM alpine:3.22 AS sslocal

# NOTE: Please be careful to change the path of these binaries, refer to #1149 for more information.
COPY --from=builder /root/shadowsocks-rust/target/release/sslocal /usr/bin/
COPY --from=builder /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/
COPY --from=builder /root/shadowsocks-rust/docker/docker-entrypoint.sh /usr/bin/

ENTRYPOINT [ "docker-entrypoint.sh" ]
CMD [ "sslocal", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]

FROM alpine:3.22 AS ssserver

COPY --from=builder /root/shadowsocks-rust/target/release/ssserver /usr/bin/
COPY --from=builder /root/shadowsocks-rust/examples/config.json /etc/shadowsocks-rust/
COPY --from=builder /root/shadowsocks-rust/docker/docker-entrypoint.sh /usr/bin/

ENTRYPOINT [ "docker-entrypoint.sh" ]

CMD [ "ssserver", "--log-without-time", "-a", "nobody", "-c", "/etc/shadowsocks-rust/config.json" ]