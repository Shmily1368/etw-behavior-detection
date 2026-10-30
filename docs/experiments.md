# Experiment protocol

## Preserved experiment programs

`original/bandwidth-collector` retains the stage-size measurement variant from the upstream `test` branch. `original/simulator` retains event-to-block conversion, serialized/compressed representations and Kafka scheduling. `magicshield.ReadData` loads `datablock`, creates producers and fake collector IDs, and schedules each data block with its original send offsets and per-client startup delays. `ReadDataProtobuf` retains the corresponding protobuf path. The original `performance-test` launch scripts are also present.

The original programs contain historical input filenames and workload settings. Supply compatible trace/block inputs and a broker for transport experiments. Existing script names, constants and compression choices are source history, not measurements of the migrated build.

## Independent measurement tools

`measure_representation.py` reports file bytes, deterministic gzip size, nonempty record counts and bytes per record. It excludes Kafka and network framing. `replay_load.py` writes a bounded schedule with simulated client IDs and scheduled/actual offsets; its stdout output is not broker throughput.

The independent CI validates asset identity, aggregation semantics, duplicate handling, process isolation, feature bounds, dictionary/version mismatch and PMML execution. Its fixtures are synthetic software-contract inputs.

## Reporting real results

Record source revision, command, configuration, data/model/dictionary hashes, hardware, Windows/JVM versions, workload, repeats and raw output. Collection experiments should distinguish event counts/loss, parsing/API coverage, CPU, peak memory and the exact stage-byte definition. Inference experiments should separate prediction latency, message consumption and end-to-end latency, with warm-up and percentile definitions.

Detection metrics require data provenance, class definitions, annotations and grouped training/test splits. Report per-class precision/recall, false-positive denominators and confusion matrices. This repository does not claim new accuracy, resource savings or throughput values from migration or compilation.
