FROM ekidd/rust-musl-builder

#ENV HTTP_PROXY="http://192.168.0.104:8118"
#ENV HTTPS_PROXY="http://192.168.0.104:8118"

ENV SODIUM_VERS="1.0.15"

# Build a static copy of libsodium.
RUN cd /home/rust/libs && \
    curl -LO https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERS.tar.gz && \
    tar xzf libsodium-$SODIUM_VERS.tar.gz && cd libsodium-$SODIUM_VERS && \
    CC=musl-gcc ./configure --prefix=/usr/local/musl && \
    make && sudo make install && \
    cd .. && rm -rf libsodium-$SODIUM_VERS.tar.gz libsodium-$SODIUM_VERS

#RUN rustup install nightly
#RUN rustup default nightly
#RUN rustup target add x86_64-unknown-linux-musl

ENV SODIUM_STATIC=yes
ENV SODIUM_LIB_DIR=/usr/local/musl/lib
