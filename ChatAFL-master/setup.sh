#!/bin/bash

if [ -z $KEY ]; then
    echo "NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    exit 0
fi

# Update the openAI key
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# Build ChatAFL-Enhanced modules with optimized flags
echo "Building ChatAFL-Enhanced modules..."
cd ChatAFL-Enhanced

# First build Enhanced modules with -O3 optimization
echo "  → Building Enhanced modules (verifier, CEGAR, scheduler)..."
make -f Makefile.enhanced clean
make -f Makefile.enhanced integrated
if [ $? -ne 0 ]; then
    echo "ERROR: ChatAFL-Enhanced modules build failed!"
    exit 1
fi

# Then build main afl-fuzz binary with -O3 optimization
echo "  → Building main afl-fuzz binary with -O3..."
make clean all
if [ $? -ne 0 ]; then
    echo "ERROR: ChatAFL-Enhanced afl-fuzz build failed!"
    exit 1
fi

cd ..
echo "ChatAFL-Enhanced built successfully (with -O3 optimization)"
echo "  Binary: $(ls -lh ChatAFL-Enhanced/afl-fuzz | awk '{print $5, $9}')"
echo "  Modules: ChatAFL-Enhanced/libchatafl-enhanced.a"

# Copy the different versions of ChatAFL to the benchmark directories
for subject in ./benchmark/subjects/*/*; do
  rm -r $subject/aflnet 2>&1 >/dev/null
  cp -r aflnet $subject/aflnet

  rm -r $subject/chatafl 2>&1 >/dev/null
  cp -r ChatAFL $subject/chatafl
  
  rm -r $subject/chatafl-cl1 2>&1 >/dev/null
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  
  rm -r $subject/chatafl-cl2 2>&1 >/dev/null
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
  
  rm -r $subject/chatafl-enhanced 2>&1 >/dev/null
  cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
done;

echo "All ChatAFL versions (including Enhanced) copied to benchmark subjects"

# Build the docker images

PFBENCH="$PWD/benchmark"
cd $PFBENCH
PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_all.sh