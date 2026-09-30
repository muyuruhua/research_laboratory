# NSFuzz-LLM: LLM-Enhanced State-Aware Network Protocol Fuzzing

This repository contains the experimental framework and evaluation scripts for NSFuzz-LLM, a state-aware network protocol fuzzer enhanced with Large Language Models (LLMs) for automatic state variable identification.

## Overview

NSFuzz-LLM extends network protocol fuzzing by using LLMs to automatically identify state-controlling variables in protocol implementations. This enables more effective state-aware fuzzing without manual state variable annotation.

### Key Features

- **LLM-Enhanced State Variable Identification**: Uses an LLM agent to automatically analyze source code and identify state-controlling variables
- **Multiple Fuzzer Support**: Includes baseline fuzzers (AFLNet) and state-aware variants (NSFuzz, NSFuzz-V, NSFuzz-LLM)
- **Comprehensive Evaluation**: Scripts for analyzing coverage, throughput, and state machine statistics
- **Docker-Based Execution**: Containerized experiments for reproducibility
- **Multiple Protocol Targets**: Supports various network protocol implementations (FTP, SSH, DNS, etc.)

## Repository Structure

```
nsfuzz-llm/
├── llm-agent/              # LLM agent for state variable identification
│   ├── agent.py           # Main agent script
│   ├── prompts/           # LLM prompts for analysis
│   ├── context/           # Context files for LLM analysis
│   └── requirements.txt   # Python dependencies
├── dockerfiles/           # Docker images for experiments, download from this link: https://mega.nz/folder/Aqw0wAST#zgfI_b0IKV3oSHi4fqO41w
├── profuzzbench_exec_all.sh      # Main execution script for all experiments
├── profuzzbench_exec_common.sh   # Common execution utilities
├── profuzzbench_generate_csv.sh  # CSV generation from results
├── generate_coverage_table.py    # Generate coverage comparison tables
├── generate_throughput_table.py  # Generate throughput comparison tables
├── generate_state_machine_stats.py # Generate state machine statistics
├── coverage_plot.py        # Generate coverage over time plots
├── commands               # Example command usage
└── exports                # Environment variable exports
```

## Prerequisites

- **Docker**: Required for running containerized experiments
- **Python 3**: Required for analysis scripts
- **LLM API Access**: OpenAI API key or compatible LLM API for state variable identification

### Python Dependencies

For analysis scripts:
```bash
pip install pandas matplotlib numpy
```

For LLM agent:
```bash
cd llm-agent
pip install -r requirements.txt
```

## Quick Start

### 1. Set Up Environment

```bash
export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH
source exports
```

### 2. Load Docker Images

Docker images are provided in the `dockerfiles/` directory. Load them using:

```bash
docker load < dockerfiles/<target>-<fuzzer>.tar.gz
```

For example:
```bash
docker load < dockerfiles/lightftp-nsfuzz-llm.tar.gz
docker load < dockerfiles/pure-ftpd-nsfuzz-llm.tar.gz
docker load < dockerfiles/openssh-nsfuzz-llm.tar.gz
```

### 3. Run Experiments

Execute fuzzing experiments using the main script:

```bash
./profuzzbench_exec_all.sh <TARGET_LIST> <FUZZER_LIST> <OUTPUT_DIR> <TIMEOUT>
```

**Parameters:**
- `TARGET_LIST`: Comma-separated list of targets (e.g., `lightftp`, `pure-ftpd`, `openssh`, or `all`)
- `FUZZER_LIST`: Comma-separated list of fuzzers (e.g., `nsfuzz-llm`, `aflnet`, `nsfuzz`, or `all`)
- `OUTPUT_DIR`: Directory to store results
- `TIMEOUT`: Fuzzing duration in seconds

**Example:**
```bash
# Run NSFuzz-LLM on LightFTP for 6 hours
NUM_CONTAINERS=3 ./profuzzbench_exec_all.sh lightftp nsfuzz-llm lightftp-result-6hr 21600

# Run all fuzzers on multiple targets
NUM_CONTAINERS=3 ./profuzzbench_exec_all.sh "lightftp,pure-ftpd" all results-6hr 21600
```

**Environment Variables:**
- `NUM_CONTAINERS`: Number of parallel containers (default: 4)
- `SKIPCOUNT`: Coverage calculation frequency (default: 1, meaning after every test case)

### 4. Generate Results CSV

Convert raw results to CSV format:

```bash
./profuzzbench_generate_csv.sh <target> <num_runs> <fuzzers> <output.csv> <append_mode>
```

**Example:**
```bash
./profuzzbench_generate_csv.sh lightftp 3 "aflnet,nsfuzz,nsfuzz-llm" coverage.csv 0
```

## Analysis Scripts

### Coverage Analysis

Generate coverage comparison tables:

```bash
python3 generate_coverage_table.py <result_directory>
```

This script processes all `*-result-6hr` directories and generates:
- `code_coverage_table.csv`: Line coverage comparison
- `branch_coverage_table.csv`: Branch coverage comparison

### Throughput Analysis

Generate fuzzing throughput comparison:

```bash
python3 generate_throughput_table.py <result_directory>
```

Generates `throughput_table.csv` with execution rates (execs/sec) for each fuzzer.

### State Machine Statistics

Generate state machine statistics from DOT files:

```bash
python3 generate_state_machine_stats.py <result_directory>
```

Generates `state_machine_stats.csv` with vertex and edge counts for each fuzzer's inferred state machine.

### Coverage Plots

Generate coverage over time plots:

```bash
python3 coverage_plot.py <coverage.csv> [--subject <target>] [--runs <num>] [--cut-off <minutes>] [--step <minutes>]
```

**Example:**
```bash
python3 coverage_plot.py coverage.csv --subject lightftp --runs 3 --cut-off 360 --step 10
```

## Supported Targets

The framework supports the following protocol implementations:

- **FTP**: `lightftp`, `pure-ftpd`, `bftpd`, `proftpd`
- **SSH**: `openssh`
- **DNS**: `dnsmasq`
- **Email**: `exim`
- **SIP**: `kamailio`
- **TLS/DTLS**: `openssl`, `tinydtls`
- **Media**: `live555`, `forked-daapd`
- **Medical**: `dcmtk`

## Supported Fuzzers

- **aflnet**: Baseline network protocol fuzzer
- **nsfuzz**: State-aware fuzzer (baseline)
- **nsfuzz-v**: State-aware fuzzer with variable tracking
- **nsfuzz-llm**: LLM-enhanced state-aware fuzzer
- **nsfuzzv-llm**: LLM-enhanced fuzzer with variable tracking

## LLM Agent Usage

The LLM agent automatically identifies state-controlling variables in protocol implementations. See `llm-agent/README.md` for detailed usage.

**Basic usage:**
```bash
cd llm-agent
export OPENAI_API_KEY="your-api-key"
python agent.py --prompt prompts/sv-cs.txt --context context/
```

The agent outputs a JSON file containing identified state variables with their types, descriptions, and code locations.

## Results Structure

After running experiments, results are organized as:

```
<output_dir>/
├── out-<target>-<fuzzer>_1.tar.gz
├── out-<target>-<fuzzer>_2.tar.gz
├── ...
└── out-<target>-<fuzzer>_<run>_sv_range_<run>.json
```

Each result archive contains:
- `cov_over_time.csv`: Coverage measurements over time
- `fuzzer_stats`: Fuzzer statistics (throughput, paths found, etc.)
- `ipsm.dot`: Inferred protocol state machine (DOT format)
- Other fuzzing artifacts

## Example Workflow

Complete example workflow for reproducing experiments:

```bash
# 1. Set up environment
export PFBENCH=$(pwd)
export PATH=$PATH:$PFBENCH
source exports

# 2. Load required Docker images
docker load < dockerfiles/lightftp-nsfuzz-llm.tar.gz
docker load < dockerfiles/lightftp-aflnet.tar.gz
docker load < dockerfiles/lightftp-nsfuzz.tar.gz

# 3. Run experiments (6 hours, 3 runs each)
NUM_CONTAINERS=3 ./profuzzbench_exec_all.sh lightftp "aflnet,nsfuzz,nsfuzz-llm" lightftp-result-6hr 21600

# 4. Generate coverage CSV
./profuzzbench_generate_csv.sh lightftp 3 "aflnet,nsfuzz,nsfuzz-llm" lightftp_coverage.csv 0

# 5. Generate analysis tables
python3 generate_coverage_table.py .
python3 generate_throughput_table.py .
python3 generate_state_machine_stats.py .

# 6. Generate plots
python3 coverage_plot.py lightftp_coverage.csv --subject lightftp --runs 3 --cut-off 360 --step 10
```

## Citation

If you use this framework in your research, please cite:

```bibtex
@article{nsfuzz-llm,
  title={NSFuzz-LLM: LLM-Enhanced State-Aware Network Protocol Fuzzing},
  author={...},
  journal={...},
  year={...}
}
```

## License

[Specify your license here]

## Contact

[Your contact information]

## Acknowledgments

This framework is based on ProfuzzBench and extends it with LLM-enhanced state variable identification capabilities.

