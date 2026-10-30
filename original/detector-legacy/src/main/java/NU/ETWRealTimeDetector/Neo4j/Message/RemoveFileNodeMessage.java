package NU.ETWRealTimeDetector.Neo4j.Message;

public class RemoveFileNodeMessage {
    public String clientId;
    public Long uuid;

    public RemoveFileNodeMessage(String clientId, Long uuid) {
        this.clientId = clientId;
        this.uuid = uuid;
    }
}
