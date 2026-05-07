FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake g++ libssl-dev make \
    && rm -rf /var/lib/apt/lists/*
COPY flashmq-src /opt/flashmq
RUN cd /opt/flashmq && mkdir -p FlashMQBuildRelease && cd FlashMQBuildRelease && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
RUN mkdir -p /var/log/flashmq /var/lib/flashmq
EXPOSE 1883
CMD ["/opt/flashmq/FlashMQBuildRelease/flashmq"]
