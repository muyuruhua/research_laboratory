# chatafl-multibroker: Lightweight multi-broker for differential testing
# Sync MBFuzzer: Mosquitto v2.0.18 (was system 2.0.11 from apt)
# Ports: 1883=Mosquitto A (default), 1884=Mosquitto B (restricted)
# Two Mosquitto v2.0.18 instances with different settings for diff testing
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential cmake libssl-dev libcjson-dev xsltproc docbook-xsl \
    netcat-openbsd ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build Mosquitto v2.0.18 from source (matches MBFuzzer)
RUN cd /opt && \
    git clone https://github.com/eclipse/mosquitto.git && \
    cd mosquitto && \
    git checkout v2.0.18 && \
    cmake -DWITH_TLS=OFF -DWITH_PERSISTENCE=OFF \
          -DDOCUMENTATION=OFF -DWITH_WEBSOCKETS=OFF \
          -DCMAKE_BUILD_TYPE=Release . && \
    make -j$(nproc) && \
    make install

RUN mkdir -p /etc/mosquitto

# Instance A config (port 1883) - default settings
RUN printf 'listener 1883 0.0.0.0\nallow_anonymous true\npersistence false\nlog_dest none\n' \
    > /etc/mosquitto/broker_a.conf

# Instance B config (port 1884) - different max settings to cause behavioral differences
RUN printf 'listener 1884 0.0.0.0\nallow_anonymous true\npersistence false\nlog_dest none\n\
max_inflight_messages 1\n\
max_queued_messages 10\n\
max_packet_size 1024\n' \
    > /etc/mosquitto/broker_b.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 1883 1884
ENTRYPOINT ["/entrypoint.sh"]
