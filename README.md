# ETW Behavior Detection

Windows behavior collection and process-level API modeling, with the original Java random-forest detector and research measurement tools.

[![Original modules](https://github.com/Shmily1368/etw-behavior-detection/actions/workflows/build-original.yml/badge.svg)](https://github.com/Shmily1368/etw-behavior-detection/actions/workflows/build-original.yml) [![Portable tools](https://github.com/Shmily1368/etw-behavior-detection/actions/workflows/verify.yml/badge.svg)](https://github.com/Shmily1368/etw-behavior-detection/actions)

## Original research system

The upstream source modules are preserved under `original/`, including the Windows collector lifecycle, process/image tracking, stack address resolution, duplicate filtering, API feature aggregation, Kafka output, Java inference, and experiment programs.

| Module | Preserved functionality |
|---|---|
| [collector-2023](original/collector-2023) | ETW collection, module/export resolution, stack pruning and process API features; the standalone original build baseline |
| [collector-2024](original/collector-2024) | Later collector and detector integrations; external upstream submodules are required for its original build |
| [detector-phf](original/detector-phf) | Original Java detector, Kafka processing, PMML inference and random-forest model |
| [detector-legacy](original/detector-legacy) | Earlier Java detector and research algorithms |
| [bandwidth-collector](original/bandwidth-collector) | Original stage-size measurement variant from the experiment branch |
| [simulator](original/simulator) | Event-to-block conversion, serialization/compression and scheduled Kafka clients |
| [performance-test](original/performance-test) | Original experiment launcher scripts |

`collector/`, `detector/` and `benchmarks/` also provide independent capture, feature replay, model inference and representation/scheduling tools. Their input and measurement contracts are documented separately from the original system.

## Build in GitHub

Open [Build original modules](https://github.com/Shmily1368/etw-behavior-detection/actions/workflows/build-original.yml) and select **Run workflow**. The default build packages the 2023 collector, bandwidth collector and three Java modules on Windows and Linux runners. Download the named EXE/DLL or JAR artifacts from the completed run. The PHF artifact includes `random_forest.pmml`.

The 2024 integration references `ThirdPart` and `InterfaceCommon` submodules that are absent from its upstream GitHub snapshot. Its optional build checks these prerequisites explicitly; it is not part of the default standalone build. See [original system and entry points](docs/original-system.md).

Windows collection runs on Windows with the original configuration files and required ETW permissions. Original Kafka applications additionally require a configured broker and the services enabled by their configuration. No macOS build environment is needed to use the GitHub build workflow.

## Model and reproducibility

The retained PMML random forest has a 2,863-position feature space, 950 active fields and 100 trees. The ordered API dictionary and model are bound by hashes in [the model manifest](models/manifest.json). Legacy group aggregation and newer stack-frequency aggregation have different semantics; the existing model is bound to its legacy feature baseline.

Compilation does not establish collection coverage, model accuracy or benchmark performance. Demonstration fixtures are synthetic. Source revisions, asset identity and measurement boundaries are recorded in the documentation.

- [Architecture](docs/architecture.md) · [Windows collectors](docs/windows-collector.md)
- [Feature methodology](docs/methodology.md) · [Model card](docs/model-card.md)
- [Experiment protocol](docs/experiments.md) · [Limitations](docs/limitations.md)
- [Provenance](docs/provenance.md) · [Third-party notices](docs/THIRD_PARTY.md)

## License

AGPL-3.0-only for repository-owned code. Existing third-party licenses and source attribution remain in force; see [LICENSE](LICENSE) and [third-party notices](docs/THIRD_PARTY.md).
