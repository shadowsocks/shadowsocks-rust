ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends build-essential cmake nasm llvm-8-dev libclang-8-dev clang-8 && \
    git config --global --add safe.directory '*' && \
    rm -rf /tmp/*

ENV GOCACHE=/tmp
