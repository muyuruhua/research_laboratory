
# syntax=docker/dockerfile-upstream:master-labs
FROM ubuntu:18.04

# Copy run.sh and set executable permission
COPY run.sh /home/ubuntu/experiments/run
RUN chmod +x /home/ubuntu/experiments/run

RUN apt-get -y update && \
    apt-get -y install sudo \ 
    apt-utils \
    build-essential \
    openssl \
    clang \
    libcurl-openssl1.0-dev \ 
    libjson-c-dev \ 
    libpcre2-dev \ 
    graphviz-dev \
    git \
    libcap-dev \
    libcurl3

# Download and compile AFLNet
ENV LLVM_CONFIG="llvm-config-6.0"

COPY ./benchmark/subjects/DAAP/forked-daapd/chatafl-enhanced/ /opt/aflnet/
WORKDIR /opt/aflnet

RUN make clean all CHATAFL_ENHANCED=1 && \
    cd llvm_mode && \
    make

# Set up environment variables for AFLNet
ENV AFLNET="/opt/aflnet"
ENV PATH="${PATH}:${AFLNET}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1
