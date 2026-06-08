FROM ubuntu:20.04

# ================================================================
# Mosquitto v2.1.2 fuzzing image for ChatAFL / ChatAFL-Opt
# ----------------------------------------------------------------
# Key diffs vs v2.0.18 Dockerfile:
#   1. libcjson-dev  — v2.1.x moved cJSON from bundled to external
#   2. cmake >= 3.18 — installed via pip3 (Ubuntu 20.04 ships 3.16)
#   3. cmake options renamed:
#        DOCUMENTATION → WITH_DOCS
#        (new) WITH_LTO=OFF      — must disable for AFL instrumentation
#        (new) WITH_TESTS=OFF    — no GTest needed
#        (new) WITH_CTRL_SHELL=OFF — no readline needed
#   4. Git repo URL: eclipse-mosquitto/mosquitto (migrated from eclipse/)
#   5. Tag: v2.1.2
# ================================================================

ENV DEBIAN_FRONTEND=noninteractive

# Step 1: core build tools
RUN apt-get -y update && \
    apt-get -y install --no-install-recommends \
    sudo \
    apt-utils \
    build-essential \
    openssl \
    clang \
    git \
    autoconf \
    llvm \
    llvm-dev \
    python3-pip \
    nano \
    net-tools \
    vim \
    gdb \
    netcat \
    strace \
    wget \
    xsltproc \
    docbook-xsl \
    pkg-config

# Step 2: library deps
# libcjson-dev: required by mosquitto >= 2.1.0 (was bundled in 2.0.x)
RUN apt-get -y install --allow-downgrades --allow-change-held-packages \
    graphviz-dev \
    libssl-dev \
    libcap-dev \
    libcurl4-openssl-dev \
    libjson-c-dev \
    nettle-dev \
    libgnutls28-dev \
    libpcre2-dev \
    libcjson-dev

# Add user ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

RUN chmod 777 /tmp

# cmake >= 3.18 required by mosquitto v2.1.2; Ubuntu 20.04 apt ships 3.16.3
# Install via pip3 so it lands in /usr/local/bin and satisfies the version check
RUN pip3 install gcovr==7.2 cmake

USER ubuntu
WORKDIR /home/ubuntu

ARG MAKE_OPT

# ── Build fuzzers (identical to v2.0.18) ──
COPY --chown=ubuntu:ubuntu aflnet aflnet
RUN cd aflnet && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

COPY --chown=ubuntu:ubuntu chatafl chatafl
RUN cd chatafl && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

COPY --chown=ubuntu:ubuntu chatafl-cl1 chatafl-cl1
RUN cd chatafl-cl1 && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

COPY --chown=ubuntu:ubuntu chatafl-cl2 chatafl-cl2
RUN cd chatafl-cl2 && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

COPY --chown=ubuntu:ubuntu chatafl-opt chatafl-opt
RUN cd chatafl-opt && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

# ── Environment variables ──
ENV WORKDIR="/home/ubuntu/experiments"
ENV AFLNET="/home/ubuntu/aflnet"
ENV PATH="${PATH}:${AFLNET}:/home/ubuntu/.local/bin:${WORKDIR}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1 \
    AFL_ENABLE_CHATAFL_OPT=1

RUN mkdir $WORKDIR

# P0-fix: Align ASAN options with all other protocol targets (FTP/SIP/SMTP/HTTP).
# Mosquitto is a C codebase — C++-specific checks (detect_container_overflow,
# poison_array_cookie, alloc_dealloc_mismatch, strict_string_checks,
# check_initialization_order, strict_init_order) add 100-500ms ASAN quarantine
# overhead during teardown without catching C bugs. Combined with the short
# kill-limit, premature SIGKILL leaks resources and causes progressive
# fuzzer stall. Matching the proven config from 6 other protocols fixes this.
ENV ASAN_OPTIONS='abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1:detect_container_overflow=0:poison_array_cookie=0:malloc_fill_byte=0:max_malloc_fill_size=16777216'

# ── Download & compile Mosquitto v2.1.2 for fuzzing ──
# Key cmake option changes vs v2.0.18:
#   -DWITH_DOCS=OFF        (was -DDOCUMENTATION=OFF)
#   -DWITH_LTO=OFF         (new in 2.1.x; MUST disable for AFL instrumentation)
#   -DWITH_TESTS=OFF       (new; avoids GTest dependency)
#   -DWITH_CTRL_SHELL=OFF  (new; avoids readline/libedit dependency)
RUN cd $WORKDIR && \
    git clone https://github.com/eclipse-mosquitto/mosquitto.git && \
    cd mosquitto && \
    git checkout v2.1.2 && \
    CC=${AFLNET}/afl-clang-fast \
    cmake -DWITH_TLS=OFF \
          -DWITH_PERSISTENCE=OFF \
          -DWITH_DOCS=OFF \
          -DWITH_WEBSOCKETS=OFF \
          -DWITH_LTO=OFF \
          -DWITH_TESTS=OFF \
          -DWITH_CTRL_SHELL=OFF \
          -DWITH_PLUGINS=OFF \
          -DCMAKE_C_FLAGS="-DMOSQUITTO_DISABLE_SLEEP" \
          -DCMAKE_BUILD_TYPE=Debug . && \
    AFL_USE_ASAN=1 make $MAKE_OPT

# ── Download & compile Mosquitto v2.1.2 for gcov coverage ──
RUN cd $WORKDIR && \
    git clone https://github.com/eclipse-mosquitto/mosquitto.git mosquitto-gcov && \
    cd mosquitto-gcov && \
    git checkout v2.1.2 && \
    cmake -DWITH_TLS=OFF \
          -DWITH_PERSISTENCE=OFF \
          -DWITH_DOCS=OFF \
          -DWITH_WEBSOCKETS=OFF \
          -DWITH_LTO=OFF \
          -DWITH_TESTS=OFF \
          -DWITH_CTRL_SHELL=OFF \
          -DWITH_PLUGINS=OFF \
          -DCMAKE_C_FLAGS="-fprofile-arcs -ftest-coverage" \
          -DCMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage" \
          -DCMAKE_BUILD_TYPE=Debug . && \
    make $MAKE_OPT

# ── Copy support files ──
COPY --chown=ubuntu:ubuntu mosquitto.conf ${WORKDIR}/mosquitto.conf
COPY --chown=ubuntu:ubuntu in-mqtt ${WORKDIR}/in-mqtt
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/run
COPY --chown=ubuntu:ubuntu cov_script.sh ${WORKDIR}/cov_script
RUN chmod +x ${WORKDIR}/run ${WORKDIR}/cov_script

USER root
WORKDIR /home/ubuntu
