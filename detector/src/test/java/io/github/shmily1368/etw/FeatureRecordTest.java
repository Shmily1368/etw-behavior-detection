// SPDX-License-Identifier: AGPL-3.0-only
package io.github.shmily1368.etw;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeatureRecordTest {
    private final ObjectMapper json = new ObjectMapper();
    private String record(String version, String values) {
        return "{\"schema_version\":\"features-v1\",\"id\":\"fixture\",\"feature_version\":\"" + version
            + "\",\"dimensions\":2863,\"api_dictionary_sha256\":\"hash\",\"provenance\":{\"kind\":\"synthetic-test\","
            + "\"description\":\"contract fixture\"},\"values\":" + values + "}";
    }
    @Test void preservesZeroBasedIndices() throws Exception {
        FeatureRecord r = FeatureRecord.parse(json.readTree(record("legacy-api-groups-v1", "[[0,0.4],[2862,0.6]]")), "hash", false);
        assertEquals(0.4, r.weights[0]);
        assertEquals(0.6, r.weights[2862]);
        assertEquals(0, r.weights[1]);
        assertEquals(0, ModelRunner.fieldIndex("x1"));
        assertEquals(2862, ModelRunner.fieldIndex("x2863"));
    }
    @Test void rejectsCorruptedOrAmbiguousFeatures() {
        for (String values : new String[]{"[[0,0.5],[0,0.5]]", "[[2863,1]]", "[[-1,1]]", "[[0,0.2]]", "[[0,2]]", "[]", "[[0.5,1]]"}) {
            assertThrows(IllegalArgumentException.class,
                () -> FeatureRecord.parse(json.readTree(record("legacy-api-groups-v1", values)), "hash", false));
        }
    }
    @Test void rejectsDictionaryAndVersionMismatch() {
        assertThrows(IllegalArgumentException.class,
            () -> FeatureRecord.parse(json.readTree(record("legacy-api-groups-v1", "[[0,1]]")), "different", false));
        assertThrows(IllegalArgumentException.class,
            () -> FeatureRecord.parse(json.readTree(record("stack-frequency-v1", "[[0,1]]")), "hash", false));
        assertDoesNotThrow(() -> FeatureRecord.parse(json.readTree(record("stack-frequency-v1", "[[0,1]]")), "hash", true));
        assertThrows(IllegalArgumentException.class, () -> ModelRunner.fieldIndex("x0"));
        assertThrows(IllegalArgumentException.class, () -> ModelRunner.fieldIndex("x2864"));
    }
    @Test void acceptsDocumentedRounding() throws Exception {
        FeatureRecord.parse(json.readTree(record("legacy-api-groups-v1", "[[0,0.3333],[1,0.3333],[2,0.3333]]")), "hash", false);
    }
}
