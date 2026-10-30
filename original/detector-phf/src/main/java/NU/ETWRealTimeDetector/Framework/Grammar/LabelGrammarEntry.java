package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;

public class LabelGrammarEntry {
    LabelType type;
    double suspiciousScore;
    double confidenceScore;
    LabelCategory category;
    String description;

    public LabelGrammarEntry(LabelType type, double suspiciousScore, double confidenceScore, LabelCategory category, String description) {
        this.type = type;
        this.suspiciousScore = suspiciousScore;
        this.confidenceScore = confidenceScore;
        this.category = category;
        this.description = description;
    }

    public LabelType getType() {
        return type;
    }

    public double getSuspiciousScore() {
        return suspiciousScore;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    public LabelCategory getCategory() {
        return category;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        LabelGrammarEntry entry = (LabelGrammarEntry) o;

        if (Double.compare(entry.suspiciousScore, suspiciousScore) != 0) return false;
        if (Double.compare(entry.confidenceScore, confidenceScore) != 0) return false;
        if (type != entry.type) return false;
        if (category != entry.category) return false;
        return description != null ? description.equals(entry.description) : entry.description == null;
    }

    @Override
    public int hashCode() {
        int result;
        long temp;
        result = type != null ? type.hashCode() : 0;
        temp = Double.doubleToLongBits(suspiciousScore);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(confidenceScore);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        result = 31 * result + (category != null ? category.hashCode() : 0);
        result = 31 * result + (description != null ? description.hashCode() : 0);
        return result;
    }
}
