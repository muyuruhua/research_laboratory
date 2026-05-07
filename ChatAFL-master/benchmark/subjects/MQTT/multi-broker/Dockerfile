# chatafl-multibroker: Lightweight multi-broker for differential testing
# Ports: 1883=Mosquitto (instance A), 1884=Mosquitto (instance B, different config)
# Two Mosquitto instances with different settings to trigger fwd_div differences
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    mosquitto netcat-openbsd procps \
    && rm -rf /var/lib/apt/lists/*

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
