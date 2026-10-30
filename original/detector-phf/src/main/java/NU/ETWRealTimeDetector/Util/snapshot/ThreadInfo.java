package NU.ETWRealTimeDetector.Util.snapshot;

public class ThreadInfo {
    Integer threadId;
    Long updateTime;
    Integer puuid;
    Integer attackerUuid;

    public ThreadInfo(Integer threadId, Long updateTime, Integer puuid, Integer attackerUuid) {
        this.threadId = threadId;
        this.updateTime = updateTime;
        this.puuid = puuid;
        this.attackerUuid = attackerUuid;
    }

    public Integer getThreadId() {
        return threadId;
    }

    public Long getUpdateTime() {
        return updateTime;
    }

    public Integer getPuuid() {
        return puuid;
    }

    public Integer getAttackerUuid() {
        return attackerUuid;
    }

    @Override
    public String toString() {
        return "ThreadInfo{" +
                "threadId=" + threadId +
                ", updateTime=" + updateTime +
                ", puuid=" + puuid +
                ", attackerUuid=" + attackerUuid +
                '}';
    }
}
