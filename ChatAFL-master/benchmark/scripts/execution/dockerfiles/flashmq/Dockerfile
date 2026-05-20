# FlashMQ Dockerfile — exact match with MBFuzzer
# MBFuzzer ref: git clone halfgaar/FlashMQ.git && git checkout d82cba5 (v1.12.1)
# Source directory flashmq-src/ is at this exact commit.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake g++ libssl-dev make \
    && rm -rf /var/lib/apt/lists/*
COPY flashmq-src /opt/flashmq
RUN cd /opt/flashmq && mkdir -p FlashMQBuildRelease && cd FlashMQBuildRelease && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
RUN mkdir -p /var/log/flashmq /var/lib/flashmq
# Ensure FlashMQ starts without a config file (uses defaults on port 1883)
EXPOSE 1883
CMD ["/opt/flashmq/FlashMQBuildRelease/flashmq"]
