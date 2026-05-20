# VerneMQ Dockerfile — EXACT match with MBFuzzer
# MBFuzzer ref: vernemq 2.0.0-rc1+build.5.reff0e6dc15 (ERTS 13.0.4)
# Source: extracted from MBFuzzer's LFS tarball
#   OID sha256:c14bd71fe72ce0715e71cdc597c2b77507ab4ad89ed3bf83d5dbe55f15b21d66
#   size 176538109
#
# MBFuzzer uses ubuntu:20.04 + esl-erlang_25.0-1~ubuntu~focal_amd64.deb
# We replicate the EXACT same OS + Erlang environment for NIF binary compat.
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Install the exact same Erlang package that MBFuzzer uses
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates libssl-dev libncurses5 libsctp1 libtinfo5 \
    libsnappy1v5 \
    && update-ca-certificates \
    && cd /tmp \
    && wget -q https://binaries2.erlang-solutions.com/ubuntu/pool/contrib/e/esl-erlang/esl-erlang_25.0-1~ubuntu~focal_amd64.deb \
    && dpkg -i esl-erlang_25.0-1~ubuntu~focal_amd64.deb \
    && apt-get install -f -y \
    && rm -rf /tmp/* /var/lib/apt/lists/*

# Copy the exact pre-built VerneMQ release extracted from MBFuzzer's LFS tarball
COPY vernemq-rel/vernemq/ /opt/vernemq/

RUN mkdir -p /opt/vernemq/data /opt/vernemq/log /opt/vernemq/etc

# Allow anonymous access for fuzzing (matches MBFuzzer conf/vernemq.conf)
ENV DOCKER_VERNEMQ_ALLOW_ANONYMOUS=on
ENV DOCKER_VERNEMQ_ACCEPT_EULA=yes
ENV VERNEMQ_PATH=/opt/vernemq
ENV PATH="${PATH}:/opt/vernemq/bin"

EXPOSE 1883
# VerneMQ 2.0.0-rc1 lacks "foreground"; start daemonized + keep-alive
CMD /opt/vernemq/bin/vernemq start && tail -f /opt/vernemq/log/console.log 2>/dev/null || tail -f /dev/null
