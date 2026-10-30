# Research model card

| Item | Verified asset information |
|---|---|
| Model | `models/random_forest.pmml` |
| PMML | 4.4 |
| Algorithm metadata | `sklearn.ensemble._forest.RandomForestClassifier` |
| Export application | JPMML-SkLearn library 1.7.6 |
| Trees | 100 |
| Input dictionary | 2,863 distinct ordered entries |
| Model feature fields | 950 `xN` fields; one additional target field |
| Mapping | `xN` → zero-based position `N-1` |
| Inference runtime | Original JPMML 1.5.11 API |
| Asset integrity | Exact SHA-256 values in `models/manifest.json` |

The PMML and API file were copied byte-for-byte from the author's selected research revision. Static metadata does not prove accuracy. Java 11 cloud inference on two synthetic fixtures was successfully executed and repeated; observed outputs are stored in `examples/expected-predictions.json`.

The original Java mapping labels `M0` RemoteShell, `M1` Keylogger, `M2` RemoteDesktop, `M6` AudioRecord, and `M7` ReverseShell. Multiple `B` codes exist, but original annotation definitions have not been verified; the public CLI preserves unknown raw class codes rather than declaring them benign.

The model returns a class and model score. The score is not established as a calibrated maliciousness probability. Remote management and audio recording may have legitimate uses.

Training data provenance, counts, annotation rules, splits, feature-selection process, hyperparameters beyond model metadata, calibration and per-class metrics remain unreproduced. Historical SVM scripts are not a reproduction of this random-forest training procedure.

The legacy feature version is a compatibility candidate derived from the old source. The full preprocessing context and original temporal flushing still require recorded-data validation. Using newer stack frequencies requires explicit experimental opt-in and independent evaluation.

Synthetic examples verify software operation only. Publish detection metrics only after labeled evaluation with documented splits and grouping to avoid same-program or same-scenario leakage.
