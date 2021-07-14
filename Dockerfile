FROM alpine:3.14 AS sslocal-builder

ENV PATH=/root/.cargo/bin:$PATH

RUN apk add build-base curl

RUN curl https://sh.rustup.rs -o rustup-init.sh && sh rustup-init.sh -y --default-toolchain nightly

WORKDIR /root/shadowsocks-rust

ADD . .

RUN cargo build --release --bin sslocal

FROM alpine:3.14 AS ssserver-builder

ENV PATH=/root/.cargo/bin:$PATH

RUN apk add build-base curl

RUN curl https://sh.rustup.rs -o rustup-init.sh && sh rustup-init.sh -y --default-toolchain nightly

WORKDIR /root/shadowsocks-rust

ADD . .

RUN cargo build --release --bin ssserver

FROM alpine:3.14 AS sslocal

COPY --from=sslocal-builder /root/shadowsocks-rust/target/release/sslocal /usr/bin/

COPY --from=sslocal-builder /root/shadowsocks-rust/examples/config_docker.json /etc/shadowsocks-rust/config.json

ENTRYPOINT [ "sslocal", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]

FROM alpine:3.14 AS ssserver

COPY --from=ssserver-builder /root/shadowsocks-rust/target/release/ssserver /usr/bin

COPY --from=ssserver-builder /root/shadowsocks-rust/examples/config_docker.json /etc/shadowsocks-rust/config.json

ENTRYPOINT [ "ssserver", "--log-without-time", "-c", "/etc/shadowsocks-rust/config.json" ]