FROM ekidd/rust-musl-builder

# Build a static copy of libsodium.
RUN VERS=1.0.15 && \
    cd /home/rust/libs && \
    curl -LO https://download.libsodium.org/libsodium/releases/libsodium-$VERS.tar.gz && \
    tar xzf libsodium-$VERS.tar.gz && cd libsodium-$VERS && \
    CC=musl-gcc ./configure --prefix=/usr/local/musl && \
    make && sudo make install && \
    cd .. && rm -rf libsodium-$VERS.tar.gz libsodium-$VERS

ENV SODIUM_STATIC=yes
ENV SODIUM_LIB_DIR=/usr/local/musl/lib
