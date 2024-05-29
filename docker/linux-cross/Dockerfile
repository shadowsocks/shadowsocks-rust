ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends build-essential cmake nasm llvm-dev libclang-dev clang  && \
    git config --global --add safe.directory '*' && \
    rm -rf /tmp/*

ENV GOCACHE=/tmp
