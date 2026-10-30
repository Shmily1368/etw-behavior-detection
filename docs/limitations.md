# Limitations

The original source modules are migrated under `original/`; collection, module/address resolution, pruning and process feature aggregation are present in those modules.

- The 2024 upstream snapshot references two external private submodules, `ThirdPart` and `InterfaceCommon`, which are not contained in the source GitHub repositories. The original 2024 integration cannot build from this snapshot alone. The default original build uses the 2023 collector and its bandwidth variant.
- The independent `etw_capture` adapter records raw events and addresses; it has a smaller scope than the original collectors. Its output is not a directly resolved PMML input.
- Independent replay uses supplied indices, caller-defined process instances and an explicit window. Original event-driven flushing and full context are separate paths.
- Legacy group aggregation and newer stack-frequency aggregation differ. The retained model is bound to the legacy feature baseline.
- PMML labels are research behavior classes. Training definitions, evaluation splits, accuracy and calibration are not established by this migration.
- Examples are synthetic. No recorded attack demonstrations or measured performance results are claimed.
- GitHub compilation checks do not prove live ETW availability, stack coverage, event-loss rates or the operation of external services.
- The independent file-size tool excludes network framing. The original simulator schedules Kafka clients within one JVM; it does not represent a real deployment across multiple hosts.
- Original private traces, logs, databases, deployment secrets and generated build outputs are excluded. Reconfigure external services and workload paths for an intended deployment.

See [original-system.md](original-system.md) for module entry points and build prerequisites.
