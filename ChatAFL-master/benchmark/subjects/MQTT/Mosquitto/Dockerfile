FROM ubuntu:20.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
# Step 1: core build tools (no version-sensitive libs yet)
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
    cmake \
    xsltproc \
    docbook-xsl \
    pkg-config

# Step 2: library deps — allow downgrades to avoid libpcre2 version conflicts
RUN apt-get -y install --allow-downgrades --allow-change-held-packages \
    graphviz-dev \
    libssl-dev \
    libcap-dev \
    libcurl4-openssl-dev \
    libjson-c-dev \
    nettle-dev \
    libgnutls28-dev \
    libpcre2-dev

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

RUN chmod 777 /tmp

RUN pip3 install gcovr==4.2

# Use ubuntu as default username
USER ubuntu
WORKDIR /home/ubuntu

# Import environment variable to pass as parameter to make (e.g., to make parallel builds with -j)
ARG MAKE_OPT

# Set up fuzzers
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

# Set up environment variables for AFLNet
ENV WORKDIR="/home/ubuntu/experiments"
ENV AFLNET="/home/ubuntu/aflnet"
ENV PATH="${PATH}:${AFLNET}:/home/ubuntu/.local/bin:${WORKDIR}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1 \
    AFL_ENABLE_CHATAFL_OPT=1

RUN mkdir $WORKDIR

# Set up environment variables for ASAN
ENV ASAN_OPTIONS='abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1:detect_container_overflow=0:poison_array_cookie=0:malloc_fill_byte=0:max_malloc_fill_size=16777216'

# Download and compile Mosquitto for fuzzing (v1.6.8 - stable fuzzing target)
RUN cd $WORKDIR && \
    git clone https://github.com/eclipse/mosquitto.git && \
    cd mosquitto && \
    git checkout v1.6.8 && \
    CC=${AFLNET}/afl-clang-fast \
    cmake -DWITH_TLS=OFF -DWITH_PERSISTENCE=OFF \
          -DDOCUMENTATION=OFF -DWITH_WEBSOCKETS=OFF \
          -DCMAKE_C_FLAGS="-DMOSQUITTO_DISABLE_SLEEP" \
          -DCMAKE_BUILD_TYPE=Debug . && \
    AFL_USE_ASAN=1 make $MAKE_OPT

# Download and compile Mosquitto for coverage analysis
RUN cd $WORKDIR && \
    git clone https://github.com/eclipse/mosquitto.git mosquitto-gcov && \
    cd mosquitto-gcov && \
    git checkout v1.6.8 && \
    cmake -DWITH_TLS=OFF -DWITH_PERSISTENCE=OFF \
          -DDOCUMENTATION=OFF -DWITH_WEBSOCKETS=OFF \
          -DCMAKE_C_FLAGS="-fprofile-arcs -ftest-coverage" \
          -DCMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage" \
          -DCMAKE_BUILD_TYPE=Debug . && \
    make $MAKE_OPT

# Copy support files
COPY --chown=ubuntu:ubuntu mosquitto.conf ${WORKDIR}/mosquitto.conf
COPY --chown=ubuntu:ubuntu in-mqtt ${WORKDIR}/in-mqtt
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/run
COPY --chown=ubuntu:ubuntu cov_script.sh ${WORKDIR}/cov_script
RUN chmod +x ${WORKDIR}/run ${WORKDIR}/cov_script

# Switch default user to root
USER root
WORKDIR /home/ubuntu
