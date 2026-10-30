# Cloud build verification

The complete migrated source snapshot was built and checked in GitHub Actions on 2026-10-30. No local macOS project build was used. The snapshot contains seven original modules and 25,620 files, including preserved vendor source and dependencies.

Verified source revision: `7a03cc87d5874faee461726ca32a97be5eed7676`.

## Results

| Job | Result | Evidence |
|---|---|---|
| windows (bandwidth-collector) | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612/job/123952564739) |
| java (simulator) | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612/job/123952564984) |
| java (detector-legacy) | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612/job/123952565008) |
| java (detector-phf) | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612/job/123952565030) |
| windows (collector-2023) | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612/job/123952565118) |
| feature-contracts | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022375162/job/123952432480) |
| java-replay | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022375162/job/123952432680) |
| windows-build | Passed | [Job](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022375162/job/123952432744) |

[Original module build](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022400612) · [Independent tool verification](https://github.com/Shmily1368/etw-behavior-detection/actions/runs/41022375162)

## Downloadable artifacts

Download packages from the artifact section of the corresponding run. The original Windows packages contain the built collector executable, retained runtime DLLs and configuration assets. The original Java packages contain JARs and their copied dependencies; the PHF package also includes `random_forest.pmml`.

| Artifact | Uploaded size |
|---|---|
| original-detector-phf-java | 157.2 MiB |
| original-collector-2023-windows-x64 | 15.0 MiB |
| original-detector-legacy-java | 150.3 MiB |
| original-simulator-java | 14.1 MiB |
| original-bandwidth-collector-windows-x64 | 15.0 MiB |
| detector-java11 | 9.0 MiB |
| collector-windows-x64 | 0.1 MiB |
| feature-contract-results | 0.0 MiB |

## Verification boundaries

Both original Windows modules and all three original Java modules compiled and packaged successfully. The portable tools also passed their feature/model contract tests and synthetic replay checks. Original Maven test execution was skipped. These checks do not establish live ETW coverage, operation of Kafka/storage services, model accuracy or benchmark performance.

The optional 2024 integration was not built: the provided upstream snapshot does not include the actual `ThirdPart` and `InterfaceCommon` submodules. Its source is preserved, and the default 2023 baseline supplies collection, address resolution, duplicate filtering and process API aggregation. See [original-system.md](original-system.md).

Legacy credential cleanup, removal of earlier build artifacts and the sanitized branch history are documented in [credential-cleanup.md](credential-cleanup.md). Old GitHub cached commit views cannot be assumed purged; exposed credentials should be invalidated by their service owner.

The machine-readable evidence is in [build-verification.json](build-verification.json).
