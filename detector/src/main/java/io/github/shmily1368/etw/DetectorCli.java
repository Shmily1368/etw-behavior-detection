// SPDX-License-Identifier: AGPL-3.0-only
package io.github.shmily1368.etw;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DetectorCli {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    static String sha256(Path path) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (java.io.InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536];
            int n;
            while ((n = input.read(buffer)) != -1) hash.update(buffer, 0, n);
        }
        StringBuilder value = new StringBuilder();
        for (byte b : hash.digest()) value.append(String.format("%02x", b & 255));
        return value.toString();
    }

    public static void main(String[] args) {
        try { run(args); }
        catch (Exception error) {
            System.err.println("detector: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            System.exit(2);
        }
    }

    static void run(String[] args) throws Exception {
        Map<String, String> options = new HashMap<>();
        boolean experimental = false;
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equals("--help")) {
                System.out.println("java -jar detector.jar --input features.ndjson --output predictions.ndjson "
                    + "--model models/random_forest.pmml --dictionary models/API.csv --manifest models/manifest.json "
                    + "[--allow-unvalidated-feature-version]");
                return;
            }
            if (args[i].equals("--allow-unvalidated-feature-version")) { experimental = true; continue; }
            if (!List.of("--input", "--output", "--model", "--dictionary", "--manifest").contains(args[i]) || i + 1 >= args.length)
                throw new IllegalArgumentException("unknown or incomplete option");
            if (options.put(args[i], args[++i]) != null)
                throw new IllegalArgumentException("duplicate option");
        }
        for (String key : List.of("--input", "--output", "--model", "--dictionary", "--manifest"))
            if (!options.containsKey(key)) throw new IllegalArgumentException(key + " is required");
        Path model = Path.of(options.get("--model")), dictionary = Path.of(options.get("--dictionary"));
        JsonNode manifest = JSON.readTree(Path.of(options.get("--manifest")).toFile());
        String modelHash = sha256(model), dictionaryHash = sha256(dictionary);
        if (!modelHash.equals(FeatureRecord.text(manifest, "model_sha256"))
            || !dictionaryHash.equals(FeatureRecord.text(manifest, "api_dictionary_sha256")))
            throw new IllegalArgumentException("model or dictionary differs from the manifest");
        List<String> apis = Files.readAllLines(dictionary, StandardCharsets.UTF_8);
        if (apis.size() != ModelRunner.DIMENSIONS || apis.stream().anyMatch(String::isBlank)
            || apis.stream().distinct().count() != ModelRunner.DIMENSIONS)
            throw new IllegalArgumentException("API dictionary must contain 2863 distinct non-empty ordered lines");
        ModelRunner runner = new ModelRunner(model);
        Path inputPath = Path.of(options.get("--input")).toAbsolutePath().normalize();
        Path outputPath = Path.of(options.get("--output")).toAbsolutePath().normalize();
        if (Files.exists(outputPath)) throw new IllegalArgumentException("output already exists");
        if (!Files.isDirectory(outputPath.getParent())) throw new IllegalArgumentException("output directory does not exist");
        Path temporary = Files.createTempFile(outputPath.getParent(), ".etw-predictions-", ".ndjson");
        long count = 0;
        try {
            try (BufferedReader input = Files.newBufferedReader(inputPath, StandardCharsets.UTF_8);
                 BufferedWriter output = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                String line;
                long lineNumber = 0;
                while ((line = input.readLine()) != null) {
                    ++lineNumber;
                    if (line.isBlank()) continue;
                    FeatureRecord record;
                    try { record = FeatureRecord.parse(JSON.readTree(line), dictionaryHash, experimental); }
                    catch (Exception error) { throw new IllegalArgumentException("invalid input at line " + lineNumber, error); }
                    ModelRunner.Prediction prediction = runner.predict(record.weights);
                    ObjectNode result = JSON.createObjectNode();
                    result.put("schema_version", "detections-v1");
                    result.put("id", record.id);
                    result.put("feature_version", record.featureVersion);
                    result.put("model_sha256", modelHash);
                    result.put("api_dictionary_sha256", dictionaryHash);
                    result.put("class_code", prediction.classCode);
                    result.put("behavior", prediction.behavior);
                    result.put("model_score", prediction.modelScore);
                    result.put("status", "classified");
                    result.put("interpretation", "behavior class; model score is not calibrated maliciousness probability");
                    result.set("input_provenance", JSON.readTree(line).get("provenance"));
                    output.write(JSON.writeValueAsString(result));
                    output.newLine();
                    ++count;
                }
            }
            if (count == 0) throw new IllegalArgumentException("no feature records found");
            Files.move(temporary, outputPath);
        } finally { Files.deleteIfExists(temporary); }
        System.err.println("Classified " + count + " feature records; output: " + outputPath.getFileName());
    }
}
