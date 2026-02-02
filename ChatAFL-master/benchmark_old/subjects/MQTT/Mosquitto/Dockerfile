FROM ubuntu:20.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    clang \
    graphviz-dev \
    git \
    autoconf \
    libgnutls28-dev \
    libssl-dev \
    llvm \
    python3-pip \
    nano \
    net-tools \
    vim \
    gdb \
    netcat \
    strace \
    libcap-dev \
    libpcre2-dev \
    libpcre2-8-0 \
    libcurl4-openssl-dev \
    curl \
    ca-certificates \
    dnsutils \
    iputils-ping \
    libjson-c-dev \
    wget \
    parallel \
    cmake \
    libcjson-dev \
    libwebsockets-dev \
    libc-ares-dev \
    uuid-dev \
    xsltproc \
    docbook-xsl

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

COPY --chown=ubuntu:ubuntu chatafl-enhanced chatafl-enhanced
RUN cd chatafl-enhanced && \
    make -f Makefile.plugin clean all CHATAFL_ENHANCED=1 $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

# Set up environment variables for AFLNet
ENV WORKDIR="/home/ubuntu/experiments"
ENV AFLNET="/home/ubuntu/aflnet"
ENV PATH="${PATH}:${AFLNET}:/home/ubuntu/.local/bin:${WORKDIR}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1

# Create experiments directory
RUN mkdir -p ${WORKDIR}

# Download and build Mosquitto MQTT broker
RUN cd ${WORKDIR} && \
    git clone https://github.com/eclipse/mosquitto.git mosquitto && \
    cd mosquitto && \
    git checkout v2.0.15

# Build standard version of Mosquitto
RUN cd ${WORKDIR}/mosquitto && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make $MAKE_OPT

# Build Mosquitto with coverage (gcov version)
RUN cd ${WORKDIR} && \
    cp -r mosquitto mosquitto-gcov && \
    cd mosquitto-gcov && \
    rm -rf CMakeCache.txt CMakeFiles && \
    cmake -DCMAKE_BUILD_TYPE=Debug \
          -DCMAKE_C_FLAGS="-fprofile-arcs -ftest-coverage" \
          -DCMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage" . && \
    make $MAKE_OPT

# Create MQTT seed inputs
RUN mkdir -p ${WORKDIR}/in-mqtt && \
    cd ${WORKDIR}/in-mqtt && \
    # CONNECT packet
    echo -ne '\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test' > mqtt_connect.raw && \
    # PUBLISH packet  
    echo -ne '\x30\x0e\x00\x08test/msg\x48\x65\x6c\x6c\x6f' > mqtt_publish.raw && \
    # SUBSCRIBE packet
    echo -ne '\x82\x0b\x00\x01\x00\x06test/#\x00' > mqtt_subscribe.raw

# Copy scripts
COPY --chown=ubuntu:ubuntu cov_script.sh ${WORKDIR}/
COPY --chown=ubuntu:ubuntu parallel_cov_wrapper.sh ${WORKDIR}/
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/
COPY --chown=ubuntu:ubuntu mqtt.dict ${WORKDIR}/

RUN chmod +x ${WORKDIR}/*.sh
