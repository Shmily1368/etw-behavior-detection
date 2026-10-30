# Original system and entry points

## Module map

| Directory under original/ | Entry point | Purpose |
|---|---|---|
| collector-2023 | `Main.cpp` and `ETWDataCollectorRedesigned.vcxproj` | Original collection and API-feature pipeline |
| bandwidth-collector | `Main.cpp` and the same project filename | Stage-size experiment variant |
| collector-2024 | `Main.cpp` and the same project filename | Later integration snapshot with external prerequisites |
| detector-phf | `NU.ETWRealTimeDetector.Main.ApiLCSDetectorMain` | Original Kafka detector with PMML call-stack processing |
| detector-legacy | `NU.ETWRealTimeDetector.Main.ApiLCSDetectorMain` | Earlier detector revision |
| simulator | `magicshield.ReadData` / `ReadDataProtobuf` | Scheduled Kafka replay of serialized blocks |
| performance-test | Preserved shell scripts | Original experiment launching |

## Cloud build

Run **Build original modules** from the GitHub Actions page. Select `all`, `windows` or `java`. The default builds the 2023 collector, bandwidth collector, both Java detectors and simulator. Artifacts preserve the EXE/DLL packages or JARs and copied dependencies. The PHF artifact also includes `random_forest.pmml`, which the original evaluator loads from its working directory.

Windows uses the existing x64 vendor libraries and MSVC v14 ABI. The CI script retargets the installed toolset/Windows SDK and normalizes search/output paths on the runner. Java builds with JDK 8 and the original Maven project dependencies. Packaging skips legacy test execution; it is not a runtime deployment test.

## Original processing chain

`etw_configuration` and collector initialization retain session setup. Event tasks and `process_info` maintain process/image context. `obtain_entry_address` retains loaded-module export/API lookup. `event_record_callstack` and `callstack_pruning` retain stack parsing/filtering. `phf_detector` retains per-process feature accumulation and original representation modes. Outputs retain JSON and Kafka paths. Java `KafkaProcessor/CallstackProcessor` loads the PMML evaluator, maps `xN` to `N-1` and returns the original behavior label mapping.

The original PMML helper's small `main` method is an old experimental test, not the recommended application entry point. Use the detector entry point above for the original service, or the independent model CLI for isolated inference.

## Runtime inputs

The collector reads its original configuration and dictionary files. Its source defines offline-log and DLL/RVA/drive-map inputs, online output settings and feature-mode options. Configure these for a Windows deployment. The Java application reads its original resource configurations, Kafka settings and optional storage/integration services. `ReadData` expects an externally prepared `datablock` and broker; its client/producer counts and startup distribution are preserved as source constants.

The migration includes source and model assets. Historical private traces, serialized workload blocks, logs, databases and deployment credentials are excluded. They are not replaced with fabricated benchmark data.

## 2024 external prerequisites

The original 2024 project references two git submodules: `ThirdPart` and `InterfaceCommon`. Their contents are absent from the provided GitHub snapshot. The archive in that repository does not contain a complete dependency/library tree; [dependency-archive.json](dependency-archive.json) records its inventory. The original project additionally names `ThirdPart/cJSON/include/cJSON.c`, which is not available in this snapshot.

The `build_2024` workflow option is disabled by default and checks these prerequisites before attempting that project. The later source is retained for comparison and continued development, but an independent build of its integration needs the actual upstream modules. The 2023 collector supplies the migrated collection, address resolution, pruning and process API aggregation baseline.
