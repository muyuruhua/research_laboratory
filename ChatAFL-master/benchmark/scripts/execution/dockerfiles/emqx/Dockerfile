# EMQX Dockerfile — exact match with MBFuzzer v5.6.0
# MBFuzzer ref: wget emqx-5.6.0-ubuntu20.04-amd64.tar.gz
# Uses official EMQX 5.6.0 image; disables auth for fuzzing (matches MBFuzzer conf)
FROM emqx/emqx:5.6.0

# EMQX 5.x env: disable authentication (allow anonymous) and strict mode
ENV EMQX_LISTENERS__TCP__DEFAULT__ENABLE_AUTHN=false
ENV EMQX_MQTT__STRICT_MODE=false
EXPOSE 1883
