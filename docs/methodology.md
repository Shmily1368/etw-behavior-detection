# Feature methodology

Two source-derived aggregation methods are preserved separately.

## `legacy-api-groups-v1`

The old vector implementation keeps a pending set of API indices per process and a previous ordered stack.

1. Empty stacks are ignored; an identical consecutive stack is filtered.
2. If the previous first frame differs from the new first frame, increment counts for the pending set and clear it.
3. Otherwise add the current stack's indices to that set.
4. Save the new stack as the previous stack.

The transition stack is not inserted into a fresh set, and an uncommitted trailing set is not flushed at end-of-input. These surprising details come from the original code and are intentionally preserved. They are documented rather than silently corrected because changing them changes the model input distribution.

## `stack-frequency-v1`

The newer implementation also filters identical consecutive stacks, then increments counts for each index in the accepted stack. The code counts the provided indices, including repeated indices in a supplied stack; address resolution upstream may apply its own frame filtering.

## Normalization and indexing

Weights are `count[i] / sum(count)` rounded to four decimal places. Sparse indices are zero-based. PMML fields retain their original one-based names: `xN` reads `weights[N-1]`. The dictionary is bound by SHA-256 and exact line order.

Dictionary shape and vector dimensions do not establish cross-method compatibility. The CLI accepts the legacy candidate by default and requires `--allow-unvalidated-feature-version` for the newer method. This switch permits experimentation, not a validated equivalence claim.

The replay input is already resolved and filtered at the API-index level. It does not recreate unavailable symbol resolution, useless-stack configuration, original window timing, or process lifecycle events. A complete compatibility claim requires recorded inputs and old/new pipeline comparison.

## Fixed contract

The synthetic sequence `[0,1], [0,1], [0,2], [3,4], [3,5], [6]` yields:

```text
legacy:    0_0.2,1_0.2,2_0.2,3_0.2,5_0.2
frequency: 0_0.2222,1_0.1111,2_0.1111,3_0.2222,4_0.1111,5_0.1111,6_0.1111
```

This is a software contract fixture with predetermined transitions; it is not recorded ETW data or detection evidence.
