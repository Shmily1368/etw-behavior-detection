// SPDX-License-Identifier: AGPL-3.0-only
package io.github.shmily1368.etw;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.dmg.pmml.FieldName;
import org.jpmml.evaluator.Evaluator;
import org.jpmml.evaluator.FieldValue;
import org.jpmml.evaluator.InputField;
import org.jpmml.evaluator.LoadingModelEvaluatorBuilder;
import org.jpmml.evaluator.ProbabilityDistribution;
import org.jpmml.evaluator.TargetField;

/** Migrates CallstackProcessor without global mutable score or silent failures. */
public final class ModelRunner {
    public static final int DIMENSIONS = 2863;
    private final Evaluator evaluator;
    private static final Map<String, String> LABELS = Map.of(
        "M0", "RemoteShell", "M1", "Keylogger", "M2", "RemoteDesktop",
        "M6", "AudioRecord", "M7", "ReverseShell"
    );

    public ModelRunner(Path model) throws Exception {
        evaluator = new LoadingModelEvaluatorBuilder().load(model.toFile()).build();
        evaluator.verify();
        for (InputField input : evaluator.getInputFields()) fieldIndex(input.getFieldName().getValue());
        if (evaluator.getTargetFields().size() != 1)
            throw new IllegalArgumentException("exactly one PMML target is required");
    }

    static int fieldIndex(String name) {
        if (!name.matches("x[1-9][0-9]*")) throw new IllegalArgumentException("invalid PMML feature field");
        int value = Integer.parseInt(name.substring(1));
        if (value > DIMENSIONS) throw new IllegalArgumentException("PMML field exceeds dictionary dimensions");
        return value - 1;
    }

    public Prediction predict(double[] weights) {
        if (weights.length != DIMENSIONS) throw new IllegalArgumentException("wrong vector dimension");
        Map<FieldName, FieldValue> arguments = new LinkedHashMap<>();
        for (InputField input : evaluator.getInputFields()) {
            double value = weights[fieldIndex(input.getFieldName().getValue())];
            if (!Double.isFinite(value) || value < 0 || value > 1)
                throw new IllegalArgumentException("invalid model input");
            arguments.put(input.getFieldName(), input.prepare(value));
        }
        Map<FieldName, ?> values = evaluator.evaluate(arguments);
        TargetField target = evaluator.getTargetFields().get(0);
        Object output = values.get(target.getName());
        if (!(output instanceof ProbabilityDistribution))
            throw new IllegalArgumentException("PMML did not return a classification distribution");
        ProbabilityDistribution distribution = (ProbabilityDistribution) output;
        String code = distribution.getResult().toString();
        double score = distribution.getValue(distribution.getResult());
        if (!Double.isFinite(score) || score < 0 || score > 1) throw new IllegalArgumentException("invalid model score");
        return new Prediction(code, LABELS.getOrDefault(code, code), score);
    }

    public static final class Prediction {
        public final String classCode;
        public final String behavior;
        public final double modelScore;
        public Prediction(String classCode, String behavior, double modelScore) {
            this.classCode = classCode;
            this.behavior = behavior;
            this.modelScore = modelScore;
        }
    }
}
