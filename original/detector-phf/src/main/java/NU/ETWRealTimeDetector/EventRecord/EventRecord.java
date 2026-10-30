package NU.ETWRealTimeDetector.EventRecord;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class EventRecord {
    public EtwEventType etwEventType;
    public int processId;
    public int threadId;
    public long timestamp;
    public String callstack;
    public Map<String, Object> argument = new HashMap();

    public EventRecord(EtwEventType etwEventType, int processId, int threadId, long timestamp) {
        this.etwEventType = etwEventType;
        this.processId = processId;
        this.threadId = threadId;
        this.timestamp = timestamp;
    }

    public EtwEventType getEtwEventType() {
        return etwEventType;
    }

    public int getProcessId() {
        return processId;
    }

    public int getThreadId() {
        return threadId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getCallstack() {
        return callstack;
    }

    public Map getArgument() {
        return argument;
    }

    public void setCallstack(String callstack) {
        this.callstack = callstack;
    }

    @Override
    public String toString() {
        return "EventRecord{" +
                "etwEventType=" + etwEventType +
                ", processId=" + processId +
                ", threadId=" + threadId +
                ", timestamp=" + timestamp +
                ", callstack='" + callstack + '\'' +
                ", argument=" + argument +
                '}';
    }

    public boolean duplicatesWith(EventRecord record) {
        if (this == record) return true;
        if (record == null) return false;
        if (processId != record.processId) return false;
        if (threadId != record.threadId) return false;
        if (etwEventType != record.etwEventType) return false;
        if (!Objects.equals(callstack, record.callstack)) return false;
        return Objects.equals(argument, record.argument);
    }

}
