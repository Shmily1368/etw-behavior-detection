# Architecture

The repository contains the original research modules and independently packaged tools.

## Original collection and detection path

`original/collector-2023` and `original/bandwidth-collector` preserve the original Windows processing chain. The 2024 snapshot preserves the later source variant, with external build prerequisites described in [original-system.md](original-system.md).

`etw_configuration` configures ETW sessions. Collector initialization and event tasks retain process/thread/image context. `process_info` and `obtain_entry_address` associate loaded modules and export addresses with API entries. `event_record_callstack` and `callstack_pruning` parse and filter stacks. `phf_detector` accumulates process-level features and emits the selected representation through the original output implementations. Java `KafkaProcessor/CallstackProcessor` maps PMML fields `xN` to vector position `N-1` and performs random-forest classification.

| Layer | Original modules | Independent tools |
|---|---|---|
| Observation and context | Complete upstream collector lifecycle, process/image tracking and providers | Bounded `etw_capture` session and raw stack records |
| Address resolution and pruning | Module/export mapping, call-stack handling and duplicate filtering | Replay accepts already-resolved API indices |
| Aggregation | Original event-driven processing and mode selection | Explicit replay window and validated process keys |
| Inference | Original Kafka detector and retained PMML model | Stateless Java model runner and checked feature records |
| Measurements | Original bandwidth branch and Kafka client scheduler | File-size comparison and bounded schedule generation |

## Independent contracts

The standalone Windows adapter emits `raw-etw-v1` observations. It does not resolve symbols itself or directly feed PMML. `feature_replay` consumes resolved-stack TSV; `pack_features.py` binds features to dictionary identity; the Java CLI checks model and feature contracts. The Python measurement tools report representation sizes or scheduled offsets.

These independent tools do not reproduce the entire original collector transport, lifecycle or automatic flushing. Keep this distinction when reporting experimental results.
