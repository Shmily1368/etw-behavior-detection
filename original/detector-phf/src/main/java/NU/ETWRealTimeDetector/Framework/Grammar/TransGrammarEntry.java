package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;

public class TransGrammarEntry {
    private String grammarRule;
    private LabelType label0;
    private EventType event;
    private LabelType label1;
    private TransDirection direction;

    public TransGrammarEntry(String grammarRule, LabelType label0, EventType event, LabelType label1, TransDirection direction) {
        this.grammarRule = grammarRule;
        this.label0 = label0;
        this.event = event;
        this.label1 = label1;
        this.direction = direction;
    }

    public String getGrammarRule() {
        return grammarRule;
    }

    public LabelType getLabel0() {
        return label0;
    }

    public EventType getEvent() {
        return event;
    }

    public LabelType getLabel1() {
        return label1;
    }

    public TransDirection getDirection() {
        return direction;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TransGrammarEntry that = (TransGrammarEntry) o;

        if (grammarRule != null ? !grammarRule.equals(that.grammarRule) : that.grammarRule != null) return false;
        if (label0 != that.label0) return false;
        if (event != that.event) return false;
        if (label1 != that.label1) return false;
        return direction == that.direction;
    }

    @Override
    public int hashCode() {
        int result = grammarRule != null ? grammarRule.hashCode() : 0;
        result = 31 * result + (label0 != null ? label0.hashCode() : 0);
        result = 31 * result + (event != null ? event.hashCode() : 0);
        result = 31 * result + (label1 != null ? label1.hashCode() : 0);
        result = 31 * result + (direction != null ? direction.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return grammarRule;
    }
}
