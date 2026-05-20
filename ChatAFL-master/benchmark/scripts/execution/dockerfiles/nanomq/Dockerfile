# NanoMQ Dockerfile — exact match with MBFuzzer
# MBFuzzer ref: git clone nanomq/nanomq.git && git checkout 236c9c5
# Build: cmake -DDEBUG=ON -DNNG_ENABLE_SQLITE=ON && make
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential cmake libsqlite3-dev ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cd /opt && \
    git clone https://github.com/nanomq/nanomq.git && \
    cd nanomq && \
    git checkout 236c9c5 && \
    git submodule update --init --recursive && \
    mkdir build && cd build && \
    cmake .. -DDEBUG=ON -DNNG_ENABLE_SQLITE=ON && \
    make -j$(nproc)

EXPOSE 1883
CMD ["/opt/nanomq/build/nanomq/nanomq", "start"]
