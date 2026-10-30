# Windows collectors

## Original modules

The original collectors live in `original/collector-2023`, `original/collector-2024` and `original/bandwidth-collector`. They include ETW session setup and lifecycle, process and image context, export-address/API resolution, stack parsing, duplicate filtering and process-level feature aggregation. The bandwidth variant preserves the original intermediate-size experiment path.

`Main.cpp` initializes logging, `Setting`, task queues, crash handling and the collector factory. Configuration selects collection/parsing and output modes. The original command-line definition includes `--mode=f` for online parsing, `--mode=p` for offline parsing, `--mode=n` for offline log collection, and `--phf_method` for the original feature/representation selection. Offline parsing needs its log, DLL/RVA and drive-map inputs; these private runtime datasets are not bundled.

Use **Build original modules** in GitHub Actions to obtain the 2023 and bandwidth EXE/DLL packages. Keep their configuration and dictionary files beside the executable. Configure broker/output options before starting live collection on an elevated Windows terminal. The 2024 integration has external prerequisites listed in [original-system.md](original-system.md).

## Independent capture adapter

`collector/` additionally contains the smaller `etw_capture` adapter. It creates an owned, bounded ETW kernel session and observes process, thread and image events with optional stack tracing. Stack payloads are length-checked and decoded at the event pointer width. QPC timestamps and frequency are retained as raw clock values.

This adapter does not perform the original module/export resolution or decode every provider-specific field. It does not stop an unrelated session and is not a replacement for the complete original pipeline. Its raw captures need an explicit resolution step before feature inference.

## Validation boundary

Cloud compilation verifies build compatibility. Live collection coverage depends on Windows, SDK/compiler, ETW privileges, provider options, workload, duration and event loss. Those runtime measurements are not inferred from a successful build.
