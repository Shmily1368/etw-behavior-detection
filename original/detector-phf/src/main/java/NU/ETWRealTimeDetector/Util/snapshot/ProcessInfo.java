package NU.ETWRealTimeDetector.Util.snapshot;

public class ProcessInfo {
    Integer uuid;
    Integer pid;
    Integer ppid;
    Integer puuid;
    Long startTime;
    Long endTime;
    Long anyMiddleTime;
    Long updateTime;
    String fileName;
    String processName;
    String cmd;

    @Override
    public String toString() {
        return "ProcessInfo{" +
                "uuid=" + uuid +
                ", pid=" + pid +
                ", ppid=" + ppid +
                ", puuid=" + puuid +
                ", startTime=" + startTime +
                ", endTime=" + endTime +
                ", anyMiddleTime=" + anyMiddleTime +
                ", updateTime=" + updateTime +
                ", fileName='" + fileName + '\'' +
                ", processName='" + processName + '\'' +
                ", cmd='" + cmd + '\'' +
                ", label='" + label + '\'' +
                '}';
    }

    public ProcessInfo(Integer uuid, Integer pid, Integer ppid, Integer puuid, Long startTime, Long endTime, Long anyMiddleTime, Long updateTime, String fileName, String processName, String cmd, String label) {
        this.uuid = uuid;
        this.pid = pid;
        this.ppid = ppid;
        this.puuid = puuid;
        this.startTime = startTime;
        this.endTime = endTime;
        this.anyMiddleTime = anyMiddleTime;
        this.updateTime = updateTime;
        this.fileName = fileName;
        this.processName = processName;
        this.cmd = cmd;
        this.label = label;
    }

    public Integer getUuid() {
        return uuid;
    }

    public Integer getPid() {
        return pid;
    }

    public Integer getPpid() {
        return ppid;
    }

    public Integer getPuuid() {
        return puuid;
    }

    public Long getStartTime() {
        return startTime;
    }

    public Long getEndTime() {
        return endTime;
    }

    public Long getAnyMiddleTime() {
        return anyMiddleTime;
    }

    public Long getUpdateTime() {
        return updateTime;
    }

    public String getFileName() {
        return fileName;
    }

    public String getProcessName() {
        return processName;
    }

    public String getCmd() {
        return cmd;
    }

    public String getLabel() {
        return label;
    }

    String label;
}
