package NU.ETWRealTimeDetector.Pojo;

import NU.ETWRealTimeDetector.Process.Process;

public class etwThread implements Comparable<etwThread> {
    private Process process;
    private int threadId;
    private long updateTime;

    public etwThread(Process process, int threadId) {
        this.process = process;
        this.threadId = threadId;
    }

    public etwThread(Process process, int threadId, long updateTime) {
        this(process, threadId);
        this.updateTime = updateTime;
    }

    public Process getProcess() {
        return process;
    }

    public int getThreadId() {
        return threadId;
    }

    public void setUpdateTime(long updateTime) {
        this.updateTime = updateTime;
    }

    public long getUpdateTime(){
        return this.updateTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        etwThread thread = (etwThread) o;

        if (threadId != thread.threadId)
            return false;
        return process != null ? process.equals(thread.process) : thread.process == null;
    }

    @Override
    public int hashCode() {
        int result = process != null ? process.hashCode() : 0;
        result = 31 * result + threadId;
        return result;
    }

    @Override
    public String toString() {
        return "etwThread{" +
                "process=" + process +
                ", threadId=" + threadId +
                '}';
    }

    @Override
    public int compareTo(etwThread o) {
        if (updateTime < o.updateTime) {
            return -1;
        } else if (updateTime > o.updateTime) {
            return 1;
        }
        return 0;
    }
}
