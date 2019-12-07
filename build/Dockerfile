ARG TOOLCHAIN=stable
FROM ekidd/rust-musl-builder:$TOOLCHAIN

ENV SODIUM_VERS="1.0.18"

# Build a static copy of libsodium.
RUN cd /home/rust/libs && \
    curl -LO https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERS.tar.gz && \
    tar xzf libsodium-$SODIUM_VERS.tar.gz && cd libsodium-$SODIUM_VERS && \
    CC=musl-gcc ./configure --prefix=/usr/local/musl --enable-shared=no --host=x86_64-unknown-linux-musl && \
    V=1 make && sudo make install && \
    cd .. && rm -rf libsodium-$SODIUM_VERS.tar.gz libsodium-$SODIUM_VERS

#ENV SODIUM_STATIC=yes
ENV SODIUM_LIB_DIR=/usr/local/musl/lib
