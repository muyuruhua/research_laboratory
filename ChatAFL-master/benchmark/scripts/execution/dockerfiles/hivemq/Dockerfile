# HiveMQ Dockerfile — exact match with MBFuzzer v4.24.0
# MBFuzzer ref: hivemq-4.24.0.zip (Enterprise)
# Docker Hub: hivemq/hivemq4:4.24.0 (exact same version)
FROM hivemq/hivemq4:4.24.0

# Allow anonymous MQTT connections for fuzzing
COPY config.xml /opt/hivemq/conf/config.xml

EXPOSE 1883
