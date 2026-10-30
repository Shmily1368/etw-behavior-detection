package NU.ETWRealTimeDetector.Neo4j.Message;

public class AddProcessNodeMessage {
    public AddProcessNodeMessage(String clientId, Long uuid, Integer pid, Long startTime, Long endTime, String processName, String commandLine) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.pid = pid;
        this.startTime = startTime;
        this.endTime = endTime;
        this.processName = processName;
        this.commandLine = commandLine;
    }

    public String clientId;
    public Long uuid;
    public Integer pid;
    public Long startTime;
    public Long endTime;
    public String processName;
    public String commandLine;
}
