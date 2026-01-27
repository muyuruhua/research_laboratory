# Mosquitto MQTT Broker - Benchmark Configuration

## Target Information
- **Protocol**: MQTT (Message Queuing Telemetry Transport)
- **Target**: Eclipse Mosquitto v2.0.15
- **Port**: 1883 (default MQTT port)
- **Type**: IoT Message Broker

## Building

```bash
# From benchmark root
sudo -E ./setup.sh

# Or build Mosquitto container only
cd subjects/MQTT/Mosquitto
docker build -t mosquitto .
```

## Running Experiments

### Basic Usage
```bash
# 60-minute experiment with ChatAFL-Enhanced
PARALLEL_MODE=1 SKIPCOUNT=10 sudo -E ./run.sh 5 60 mosquitto chatafl-enhanced

# 10-minute quick test
PARALLEL_MODE=1 sudo -E ./run.sh 3 10 mosquitto aflnet
```

### Environment Variables
- `PARALLEL_MODE=1`: Enable parallel coverage collection (recommended)
- `SKIPCOUNT=10`: Sample coverage every 10 test cases
- `SKIP_GCOVR_HTML=1`: Skip HTML coverage report generation

## MQTT Protocol Specifics

### Supported Packet Types
- CONNECT/CONNACK: Connection establishment
- PUBLISH/PUBACK: Message publishing
- SUBSCRIBE/SUBACK: Topic subscription  
- UNSUBSCRIBE/UNSUBACK: Unsubscription
- PINGREQ/PINGRESP: Keep-alive
- DISCONNECT: Clean disconnection

### Seed Inputs
Located in `/home/ubuntu/experiments/in-mqtt/`:
- `mqtt_connect.raw`: CONNECT packet with client ID
- `mqtt_publish.raw`: PUBLISH to test/msg topic
- `mqtt_subscribe.raw`: SUBSCRIBE to test/# wildcard

## OCP Compliance

This benchmark follows the Open-Closed Principle:
- ✅ `cov_script.sh`: Original serial coverage (untouched)
- ✅ `parallel_cov_wrapper.sh`: Parallel extension (new file)
- ✅ `run.sh`: Strategy selector (minimal modification)
- ✅ Graceful degradation: Falls back if GNU parallel unavailable

## Performance Expectations

Based on similar protocol complexity (comparable to RTSP/Live555):
- **Test cases (10-min)**: ~150-250
- **Coverage time (serial)**: ~18-30 minutes
- **Coverage time (parallel)**: ~5-8 minutes
- **Expected speedup**: ~3-4x with parallel mode

## References

- Mosquitto Documentation: https://mosquitto.org/documentation/
- MQTT Specification: https://mqtt.org/mqtt-specification/
- AFLNet MQTT Testing: Uses stateful fuzzing for protocol compliance

## Notes

- Mosquitto runs in non-persistent mode for reproducibility
- Anonymous connections allowed (no authentication during fuzzing)
- All logging redirected to stdout for debugging
- Coverage collected from both broker core and plugin modules
