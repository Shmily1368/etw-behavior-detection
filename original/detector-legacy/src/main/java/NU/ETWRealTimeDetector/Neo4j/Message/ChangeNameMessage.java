package NU.ETWRealTimeDetector.Neo4j.Message;

public class ChangeNameMessage {
    public ChangeNameMessage(String clientId, Long oldFileNodeUuid, Long newFileNodeUuid, String newFileName) {
        this.clientId = clientId;
        this.oldFileNodeUuid = oldFileNodeUuid;
        this.newFileNodeUuid = newFileNodeUuid;
        this.newFileName = newFileName;
    }

    public String clientId;
    public Long oldFileNodeUuid;
    public Long newFileNodeUuid;
    public String newFileName;
}
