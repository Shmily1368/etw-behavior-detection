package NU.ETWRealTimeDetector.Cache;

import NU.ETWRealTimeDetector.Process.Process;

public class TraceKey {
    private String clientID;
    private Process process;
    private int tid;

    public TraceKey(String clientID, Process process, int tid) {
        this.clientID = clientID;
        this.process = process;
        this.tid = tid;
    }

    public String getClientID() {
        return clientID;
    }

    public Process getProcess() {
        return process;
    }

    public int getTid() {
        return tid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TraceKey traceKey = (TraceKey) o;

        if (tid != traceKey.tid) return false;
        if (clientID != null ? !clientID.equals(traceKey.clientID) : traceKey.clientID != null) return false;
        return process != null ? process.equals(traceKey.process) : traceKey.process == null;
    }

    @Override
    public int hashCode() {
        int result = clientID != null ? clientID.hashCode() : 0;
        result = 31 * result + (process != null ? process.hashCode() : 0);
        result = 31 * result + tid;
        return result;
    }

    @Override
    public String toString() {
        return String.format("%s_%s_%d", clientID, process.toString(), tid);
    }
}
