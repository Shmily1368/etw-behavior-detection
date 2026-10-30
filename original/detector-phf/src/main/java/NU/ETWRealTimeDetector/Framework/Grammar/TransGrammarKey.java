package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;

public class TransGrammarKey {
    LabelType labelType;
    EventType eventType;
    TransDirection direction;

    public TransGrammarKey(LabelType labelType, EventType eventType, TransDirection direction) {
        this.labelType = labelType;
        this.eventType = eventType;
        this.direction = direction;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TransGrammarKey that = (TransGrammarKey) o;

        if (labelType != that.labelType) return false;
        if (eventType != that.eventType) return false;
        return direction == that.direction;
    }

    @Override
    public int hashCode() {
        int result = labelType != null ? labelType.hashCode() : 0;
        result = 31 * result + (eventType != null ? eventType.hashCode() : 0);
        result = 31 * result + (direction != null ? direction.hashCode() : 0);
        return result;
    }
}
