// SPDX-License-Identifier: AGPL-3.0-only
package io.github.shmily1368.etw;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashSet;
import java.util.Set;

public final class FeatureRecord {
    public final String id;
    public final String featureVersion;
    public final double[] weights;

    private FeatureRecord(String id, String featureVersion, double[] weights) {
        this.id = id;
        this.featureVersion = featureVersion;
        this.weights = weights;
    }

    static String text(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual() || value.textValue().isBlank())
            throw new IllegalArgumentException("missing or invalid " + key);
        return value.textValue();
    }

    public static FeatureRecord parse(JsonNode node, String dictionaryHash, boolean allowExperimental) {
        if (!node.isObject()) throw new IllegalArgumentException("feature must be a JSON object");
        if (!"features-v1".equals(text(node, "schema_version")))
            throw new IllegalArgumentException("unsupported feature schema");
        String id = text(node, "id");
        String version = text(node, "feature_version");
        if (!version.equals("legacy-api-groups-v1") && !(allowExperimental && version.equals("stack-frequency-v1")))
            throw new IllegalArgumentException("unvalidated feature version; use the experimental option explicitly");
        if (!dictionaryHash.equals(text(node, "api_dictionary_sha256")))
            throw new IllegalArgumentException("API dictionary hash mismatch");
        JsonNode dimensions = node.get("dimensions");
        if (dimensions == null || !dimensions.isIntegralNumber() || !dimensions.canConvertToInt()
            || dimensions.intValue() != ModelRunner.DIMENSIONS)
            throw new IllegalArgumentException("wrong feature dimensions");
        JsonNode provenance = node.get("provenance");
        if (provenance == null || !provenance.isObject())
            throw new IllegalArgumentException("input provenance required");
        String kind = text(provenance, "kind");
        if (!Set.of("synthetic-test", "collected", "imported").contains(kind))
            throw new IllegalArgumentException("unsupported provenance kind");
        text(provenance, "description");
        JsonNode entries = node.get("values");
        if (entries == null || !entries.isArray() || entries.isEmpty())
            throw new IllegalArgumentException("non-empty sparse features required");
        double[] weights = new double[ModelRunner.DIMENSIONS];
        Set<Integer> seen = new HashSet<>();
        double sum = 0;
        for (JsonNode entry : entries) {
            if (!entry.isArray() || entry.size() != 2 || !entry.get(0).isIntegralNumber()
                || !entry.get(0).canConvertToInt() || !entry.get(1).isNumber())
                throw new IllegalArgumentException("sparse values must be [integer index, numeric weight]");
            int index = entry.get(0).intValue();
            double weight = entry.get(1).doubleValue();
            if (index < 0 || index >= weights.length || !seen.add(index))
                throw new IllegalArgumentException("duplicate or out-of-range sparse index");
            if (!Double.isFinite(weight) || weight < 0 || weight > 1)
                throw new IllegalArgumentException("invalid sparse weight");
            weights[index] = weight;
            sum += weight;
        }
        // Four-decimal rounding from the source algorithm: at most 0.00005
        // error per serialized entry, plus a small floating-point allowance.
        double tolerance = entries.size() * 0.00005 + 1e-9;
        if (Math.abs(sum - 1.0) > tolerance)
            throw new IllegalArgumentException("sparse weights do not match normalized frequency semantics");
        return new FeatureRecord(id, version, weights);
    }
}
