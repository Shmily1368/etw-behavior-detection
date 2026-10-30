# Provenance and consolidation

The repository consolidates the upstream ETW research source snapshots while retaining existing source attribution and third-party notices. The original private repositories and their histories remain separate.

| Source | Pinned revision | Migrated modules |
|---|---|---|
| ETWDataCollector / main | `8591e0a7edb15924969d993a3bb5476bb820377a` | 2023 collector and Java detector modules |
| ETWCollector_2024 / main | `58b0dc626c8ac06a86f3d1e262f309791b6db056` | 2024 collector snapshot |
| ETWDataCollector / test | `0a255cdb095a9feb18727cec6bffd31a4172426d` | Bandwidth collector, simulator and experiment scripts |

[full-source-migration.json](full-source-migration.json) records the initial migration inventory. [source-manifest.json](source-manifest.json) records the current published source trees after dependency recovery and cloud compatibility changes. Initial exclusions include generated builds, logs, databases, traces and deployment-only material. Required inline dependency sources were subsequently restored.

Private endpoint defaults and credential literals were scrubbed. The original Kafka username/password logging statement was removed. Windows compatibility changes make required standard headers explicit, restrict library search to x64 inputs and preserve existing vendored Boost libraries rather than deriving incompatible auto-link filenames. Duplicate Maven dependency entries were removed. These changes do not replace the original aggregation or model algorithms.

The 2024 snapshot's missing `ThirdPart` and `InterfaceCommon` submodules originate outside the provided GitHub source repositories; see [original-system.md](original-system.md). No source for these unavailable modules is invented or represented as migrated.

Independent tools in `collector/`, `detector/` and `benchmarks/` isolate selected functionality into explicit input/output contracts. They are separate packaging work alongside the preserved original modules. Model and dictionary asset identity is recorded in `models/manifest.json`.

Repository-owned code is AGPL-3.0-only. Existing component licenses and attribution are retained; see [THIRD_PARTY.md](THIRD_PARTY.md).
