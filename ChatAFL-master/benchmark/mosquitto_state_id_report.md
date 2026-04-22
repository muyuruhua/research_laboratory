# Mosquitto IPSM state ID report

## Run mapping

The 4 runs come from these benchmark summaries:

- [benchmark/results-mosquitto-v2.0.18_Apr-22_00-06-37/run_summary.csv](benchmark/results-mosquitto-v2.0.18_Apr-22_00-06-37/run_summary.csv)
  - `v2.0.18-r1` = `out-mosquitto-v2.0.18-chatafl_opt_1.tar.gz`
  - `v2.0.18-r2` = `out-mosquitto-v2.0.18-chatafl_opt_2.tar.gz`
- [benchmark/results-mosquitto-v2.1.2_Apr-22_00-06-37/run_summary.csv](benchmark/results-mosquitto-v2.1.2_Apr-22_00-06-37/run_summary.csv)
  - `v2.1.2-r1` = `out-mosquitto-v2.1.2-chatafl_opt_1.tar.gz`
  - `v2.1.2-r2` = `out-mosquitto-v2.1.2-chatafl_opt_2.tar.gz`

## State ID encoding

`ChatAFL-Opt` encodes MQTT IPSM state IDs as follows:

- plain response packet: `state_id = packet_type << 4`
- response with reason/return code: `state_id = ((packet_type << 4) << 8) | reason_code`
- forwarded `PUBLISH` special-case: `state_id = 0x3000 | (qos + 1)`

The decoder is implemented in [ChatAFL-Opt/aflnet.c](ChatAFL-Opt/aflnet.c#L1603-L1700).

## Full table: ID → semantic → runs

| ID(dec) | ID(hex) | Semantic | Runs |
|---:|---:|---|---|
| 32 | 0x20 | CONNACK | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 64 | 0x40 | PUBACK | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 80 | 0x50 | PUBREC | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 96 | 0x60 | PUBREL | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 112 | 0x70 | PUBCOMP | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 144 | 0x90 | SUBACK | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 176 | 0xb0 | UNSUBACK | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 208 | 0xd0 | PINGRESP | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 224 | 0xe0 | DISCONNECT | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 240 | 0xf0 | AUTH | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8193 | 0x2001 | CONNACK + granted QoS 1 / v3 connack code 1 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1 |
| 8194 | 0x2002 | CONNACK + granted QoS 2 / v3 connack code 2 | v2.0.18-r1, v2.0.18-r2 |
| 8241 | 0x2031 | CONNACK + reason 0x31 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8274 | 0x2052 | CONNACK + reason 0x52 | v2.1.2-r1, v2.1.2-r2 |
| 8275 | 0x2053 | CONNACK + reason 0x53 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8281 | 0x2059 | CONNACK + reason 0x59 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8289 | 0x2061 | CONNACK + reason 0x61 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8290 | 0x2062 | CONNACK + reason 0x62 | v2.1.2-r1, v2.1.2-r2 |
| 8291 | 0x2063 | CONNACK + reason 0x63 | v2.1.2-r1, v2.1.2-r2 |
| 8293 | 0x2065 | CONNACK + reason 0x65 | v2.0.18-r1, v2.0.18-r2 |
| 8296 | 0x2068 | CONNACK + reason 0x68 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8297 | 0x2069 | CONNACK + reason 0x69 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8301 | 0x206d | CONNACK + reason 0x6d | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8302 | 0x206e | CONNACK + reason 0x6e | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8303 | 0x206f | CONNACK + reason 0x6f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8304 | 0x2070 | CONNACK + reason 0x70 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8306 | 0x2072 | CONNACK + reason 0x72 | v2.1.2-r1, v2.1.2-r2 |
| 8307 | 0x2073 | CONNACK + reason 0x73 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8308 | 0x2074 | CONNACK + reason 0x74 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 8309 | 0x2075 | CONNACK + reason 0x75 | v2.1.2-r1, v2.1.2-r2 |
| 8310 | 0x2076 | CONNACK + reason 0x76 | v2.1.2-r1, v2.1.2-r2 |
| 8313 | 0x2079 | CONNACK + reason 0x79 | v2.0.18-r1, v2.0.18-r2 |
| 8322 | 0x2082 | CONNACK + protocol error | v2.1.2-r1, v2.1.2-r2 |
| 8324 | 0x2084 | CONNACK + unsupported protocol version | v2.1.2-r1, v2.1.2-r2 |
| 8332 | 0x208c | CONNACK + bad authentication method | v2.0.18-r2 |
| 12289 | 0x3001 | PUBLISH-forwarded, QoS 0 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 12290 | 0x3002 | PUBLISH-forwarded, QoS 1 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 12291 | 0x3003 | PUBLISH-forwarded, QoS 2 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 12292 | 0x3004 | PUBLISH-forwarded, QoS 3 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1 |
| 16387 | 0x4003 | PUBACK + v3 connack code 3 | v2.1.2-r2 |
| 16416 | 0x4020 | PUBACK + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 16432 | 0x4030 | PUBACK + reason 0x30 | v2.1.2-r1 |
| 16433 | 0x4031 | PUBACK + reason 0x31 | v2.0.18-r1 |
| 16434 | 0x4032 | PUBACK + reason 0x32 | v2.1.2-r1 |
| 16440 | 0x4038 | PUBACK + reason 0x38 | v2.0.18-r2 |
| 16441 | 0x4039 | PUBACK + reason 0x39 | v2.0.18-r1 |
| 16449 | 0x4041 | PUBACK + reason 0x41 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 16450 | 0x4042 | PUBACK + reason 0x42 | v2.0.18-r2 |
| 16454 | 0x4046 | PUBACK + reason 0x46 | v2.1.2-r1 |
| 16468 | 0x4054 | PUBACK + reason 0x54 | v2.1.2-r1 |
| 20483 | 0x5003 | PUBREC + v3 connack code 3 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 20499 | 0x5013 | PUBREC + reason 0x13 | v2.0.18-r1, v2.0.18-r2 |
| 20512 | 0x5020 | PUBREC + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 20529 | 0x5031 | PUBREC + reason 0x31 | v2.1.2-r2 |
| 20545 | 0x5041 | PUBREC + reason 0x41 | v2.1.2-r2 |
| 20575 | 0x505f | PUBREC + reason 0x5f | v2.0.18-r1, v2.1.2-r1 |
| 20578 | 0x5062 | PUBREC + reason 0x62 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 20591 | 0x506f | PUBREC + reason 0x6f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 20594 | 0x5072 | PUBREC + reason 0x72 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 20605 | 0x507d | PUBREC + reason 0x7d | v2.1.2-r1, v2.1.2-r2 |
| 20624 | 0x5090 | PUBREC + topic name invalid | v2.0.18-r1, v2.0.18-r2 |
| 20626 | 0x5092 | PUBREC + packet identifier not found | v2.1.2-r1 |
| 20629 | 0x5095 | PUBREC + packet too large | v2.1.2-r1, v2.1.2-r2 |
| 24577 | 0x6001 | PUBREL + granted QoS 1 / v3 connack code 1 | v2.1.2-r2 |
| 24584 | 0x6008 | PUBREL + reason 0x08 | v2.0.18-r1, v2.1.2-r1 |
| 24597 | 0x6015 | PUBREL + reason 0x15 | v2.1.2-r1 |
| 24598 | 0x6016 | PUBREL + reason 0x16 | v2.1.2-r1, v2.1.2-r2 |
| 24604 | 0x601c | PUBREL + reason 0x1c | v2.1.2-r2 |
| 24605 | 0x601d | PUBREL + reason 0x1d | v2.0.18-r2 |
| 24608 | 0x6020 | PUBREL + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24609 | 0x6021 | PUBREL + reason 0x21 | v2.1.2-r2 |
| 24612 | 0x6024 | PUBREL + reason 0x24 | v2.0.18-r1 |
| 24621 | 0x602d | PUBREL + reason 0x2d | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24622 | 0x602e | PUBREL + reason 0x2e | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24623 | 0x602f | PUBREL + reason 0x2f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24624 | 0x6030 | PUBREL + reason 0x30 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24625 | 0x6031 | PUBREL + reason 0x31 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24626 | 0x6032 | PUBREL + reason 0x32 | v2.1.2-r1, v2.1.2-r2 |
| 24628 | 0x6034 | PUBREL + reason 0x34 | v2.1.2-r1 |
| 24630 | 0x6036 | PUBREL + reason 0x36 | v2.1.2-r2 |
| 24649 | 0x6049 | PUBREL + reason 0x49 | v2.1.2-r1, v2.1.2-r2 |
| 24663 | 0x6057 | PUBREL + reason 0x57 | v2.1.2-r1 |
| 24671 | 0x605f | PUBREL + reason 0x5f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24673 | 0x6061 | PUBREL + reason 0x61 | v2.1.2-r1, v2.1.2-r2 |
| 24674 | 0x6062 | PUBREL + reason 0x62 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24675 | 0x6063 | PUBREL + reason 0x63 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24676 | 0x6064 | PUBREL + reason 0x64 | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 24677 | 0x6065 | PUBREL + reason 0x65 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24678 | 0x6066 | PUBREL + reason 0x66 | v2.0.18-r1, v2.0.18-r2 |
| 24679 | 0x6067 | PUBREL + reason 0x67 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24680 | 0x6068 | PUBREL + reason 0x68 | v2.0.18-r1, v2.0.18-r2 |
| 24681 | 0x6069 | PUBREL + reason 0x69 | v2.1.2-r1, v2.1.2-r2 |
| 24683 | 0x606b | PUBREL + reason 0x6b | v2.1.2-r1, v2.1.2-r2 |
| 24684 | 0x606c | PUBREL + reason 0x6c | v2.0.18-r1, v2.0.18-r2, v2.1.2-r2 |
| 24685 | 0x606d | PUBREL + reason 0x6d | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24686 | 0x606e | PUBREL + reason 0x6e | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 24687 | 0x606f | PUBREL + reason 0x6f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24688 | 0x6070 | PUBREL + reason 0x70 | v2.1.2-r1, v2.1.2-r2 |
| 24690 | 0x6072 | PUBREL + reason 0x72 | v2.1.2-r1, v2.1.2-r2 |
| 24691 | 0x6073 | PUBREL + reason 0x73 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24692 | 0x6074 | PUBREL + reason 0x74 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24693 | 0x6075 | PUBREL + reason 0x75 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 24694 | 0x6076 | PUBREL + reason 0x76 | v2.1.2-r1, v2.1.2-r2 |
| 24697 | 0x6079 | PUBREL + reason 0x79 | v2.0.18-r1, v2.0.18-r2 |
| 24800 | 0x60e0 | PUBREL + reason 0xe0 | v2.1.2-r1 |
| 28675 | 0x7003 | PUBCOMP + v3 connack code 3 | v2.1.2-r1, v2.1.2-r2 |
| 28681 | 0x7009 | PUBCOMP + reason 0x09 | v2.0.18-r1 |
| 28697 | 0x7019 | PUBCOMP + re-authenticate | v2.1.2-r2 |
| 28701 | 0x701d | PUBCOMP + reason 0x1d | v2.0.18-r1, v2.0.18-r2 |
| 28704 | 0x7020 | PUBCOMP + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28707 | 0x7023 | PUBCOMP + reason 0x23 | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 28719 | 0x702f | PUBCOMP + reason 0x2f | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 28720 | 0x7030 | PUBCOMP + reason 0x30 | v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28721 | 0x7031 | PUBCOMP + reason 0x31 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28723 | 0x7033 | PUBCOMP + reason 0x33 | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 28769 | 0x7061 | PUBCOMP + reason 0x61 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28770 | 0x7062 | PUBCOMP + reason 0x62 | v2.1.2-r1, v2.1.2-r2 |
| 28771 | 0x7063 | PUBCOMP + reason 0x63 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1 |
| 28772 | 0x7064 | PUBCOMP + reason 0x64 | v2.0.18-r1, v2.1.2-r2 |
| 28773 | 0x7065 | PUBCOMP + reason 0x65 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28777 | 0x7069 | PUBCOMP + reason 0x69 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28780 | 0x706c | PUBCOMP + reason 0x6c | v2.1.2-r1, v2.1.2-r2 |
| 28781 | 0x706d | PUBCOMP + reason 0x6d | v2.0.18-r1, v2.0.18-r2, v2.1.2-r2 |
| 28782 | 0x706e | PUBCOMP + reason 0x6e | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28783 | 0x706f | PUBCOMP + reason 0x6f | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28784 | 0x7070 | PUBCOMP + reason 0x70 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1 |
| 28786 | 0x7072 | PUBCOMP + reason 0x72 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28787 | 0x7073 | PUBCOMP + reason 0x73 | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 28788 | 0x7074 | PUBCOMP + reason 0x74 | v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 28789 | 0x7075 | PUBCOMP + reason 0x75 | v2.1.2-r1, v2.1.2-r2 |
| 28790 | 0x7076 | PUBCOMP + reason 0x76 | v2.1.2-r1, v2.1.2-r2 |
| 28793 | 0x7079 | PUBCOMP + reason 0x79 | v2.1.2-r1, v2.1.2-r2 |
| 28816 | 0x7090 | PUBCOMP + topic name invalid | v2.1.2-r1, v2.1.2-r2 |
| 36865 | 0x9001 | SUBACK + granted QoS 1 / v3 connack code 1 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 36866 | 0x9002 | SUBACK + granted QoS 2 / v3 connack code 2 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 36886 | 0x9016 | SUBACK + reason 0x16 | v2.0.18-r1, v2.1.2-r1, v2.1.2-r2 |
| 36896 | 0x9020 | SUBACK + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 36913 | 0x9031 | SUBACK + reason 0x31 | v2.1.2-r1, v2.1.2-r2 |
| 36915 | 0x9033 | SUBACK + reason 0x33 | v2.1.2-r1, v2.1.2-r2 |
| 37008 | 0x9090 | SUBACK + topic name invalid | v2.1.2-r1, v2.1.2-r2 |
| 45067 | 0xb00b | UNSUBACK + reason 0x0b | v2.1.2-r1, v2.1.2-r2 |
| 45088 | 0xb020 | UNSUBACK + reason 0x20 | v2.0.18-r1, v2.0.18-r2, v2.1.2-r1, v2.1.2-r2 |
| 45200 | 0xb090 | UNSUBACK + topic name invalid | v2.1.2-r2 |
| 61565 | 0xf07d | AUTH + reason 0x7d | v2.1.2-r1, v2.1.2-r2 |
| 61632 | 0xf0c0 | AUTH + reason 0xc0 | v2.1.2-r2 |
| 61678 | 0xf0ee | AUTH + reason 0xee | v2.0.18-r1, v2.0.18-r2 |

## Error CONNACK seeds

### 1) `0x2082` = `CONNACK + Protocol Error`

- Appears in:
  - `v2.1.2-r1`: `responses-ipsm/id:id:000701,src:000000+000488,op:mqtt_explore,rep:16,+cov`
  - `v2.1.2-r2`: `responses-ipsm/id:id:000523,src:000000,op:mqtt_exploit,rep:128,+cov`
- Representative trigger seed:
  - `queue/id:000701,src:000000+000488,op:mqtt_explore,rep:16,+cov`
- Packet sequence in the seed:
  - malformed/overloaded `CONNECT`
  - `SUBSCRIBE test/#`
  - `PINGREQ`
- The first packet is still structurally a v5 `CONNECT`:
  - protocol = `MQTT`
  - version = `5`
  - flags = `0xc2`
  - keepalive = `110`
  - properties include:
    - `Receive Maximum = 62782`
    - `Topic Alias Maximum = 25295`
    - `Request Response Information = 90`
    - `Request Problem Information = 79`
    - `User Property = ('$share/grp/test/topic', '$share/grp1/test/+')`
    - `Authentication Method = 'a/b/c/d/e'`
    - `Authentication Data = a94dee49d106dbdcd1c49a15fe864a50c52d8b`
  - payload includes `ClientId = gen_v5_sub`, `Username = fuzz_user`, `Password = fuzz_pass`
- Interpretation:
  - This is **not** a simple version mismatch; it is a syntactically v5 `CONNECT` carrying a very aggressive combination of CONNECT properties and auth-related fields.
  - The broker answers with `20 03 00 82 00`, i.e. v5 `CONNACK` reason `0x82` = `Protocol Error`.
  - The provenance `src:000000+000488` shows it was built from the base connect seed plus another mutated fragment, so this node is triggered by a **spliced multi-packet input where the first CONNECT remains parseable but semantically invalid**.

### 2) `0x2084` = `CONNACK + Unsupported Protocol Version`

- Appears in:
  - `v2.1.2-r1`: `responses-ipsm/id:id:000476,src:000000,op:mqtt_explore,rep:8,+cov`
  - `v2.1.2-r2`: `responses-ipsm/id:id:000474,src:000000,op:mqtt_exploit,rep:2,+cov`
- Representative trigger seed:
  - `queue/id:000476,src:000000,op:mqtt_explore,rep:8,+cov`
- Packet sequence in the seed:
  - corrupted `CONNECT`
  - `SUBSCRIBE test/#`
  - `PINGREQ`
- The first packet bytes are:
  - `10 15 00 04 05 02 00 3c 11 09 61 66 6c 6e 00 00 01 00 54 54 04 02 00`
- Compare with the base seed `id:000000,orig:enriched_0_mqtt_connect`:
  - base first packet = `10 15 00 04 4d 51 54 54 04 02 00 3c 00 09 61 66 6c 6e 65 74 5f 63 30`
  - i.e. normal MQTT 3.1.1 `CONNECT` with protocol name `MQTT`, version `4`, keepalive `60`, client id `aflnet_c0`
- Interpretation:
  - `id:000476` is a mutation of the base connect seed where the **protocol name / protocol header bytes are smashed**.
  - The broker returns `20 03 00 84 00`, i.e. v5 `CONNACK` reason `0x84` = `Unsupported Protocol Version`.
  - So this IPSM node corresponds to a **header-corruption path on CONNECT**, not a later session-state transition.

### 3) `0x208c` = `CONNACK + Bad authentication method`

- Appears in:
  - `v2.0.18-r2`: `responses-ipsm/id:id:000609,src:000000,op:mqtt_exploit,rep:32,+cov`
- Representative trigger seed:
  - `queue/id:000609,src:000000,op:mqtt_exploit,rep:32,+cov`
- Packet sequence in the seed:
  - v5 `CONNECT`
  - `SUBSCRIBE test/#`
  - `PINGREQ`
- The first packet is a v5 `CONNECT` with:
  - protocol = `MQTT`
  - version = `5`
  - flags = `0x02`
  - keepalive = `55`
  - properties include:
    - `Receive Maximum = 14512`
    - `Maximum Packet Size = 1676940907`
    - `User Property = ('$share/grp1/#', 't')`
    - `Authentication Method = ''` (empty string)
    - `Authentication Data = 770a3e0e26f4afeab393617c3fab`
  - payload includes `ClientId = gen_v5_sub`
- Interpretation:
  - This one is the cleanest semantically: it is a v5 `CONNECT` that explicitly carries **Authentication Method + Authentication Data**, but the method string is empty.
  - The broker returns `20 03 00 8c 00`, i.e. v5 `CONNACK` reason `0x8c` = `Bad authentication method`.
  - Therefore `0x208c` is a **v5 enhanced-auth validation node** reached by mutating the base connect seed into a malformed auth-method CONNECT.

## Bottom line

- The three queried error states are all **CONNECT-rejection states**, not deeper broker session states.
- `0x2084` comes from a **corrupted CONNECT header**.
- `0x2082` comes from a **syntactically parseable but semantically invalid v5 CONNECT** with an over-aggressive property/auth combination.
- `0x208c` comes from a **v5 CONNECT with invalid authentication method metadata**.
- In all three cases the rest of the sequence still contains `SUBSCRIBE test/#` and `PINGREQ`, but those later packets are irrelevant once the broker rejects the initial CONNECT.
