package NU.ETWRealTimeDetector.Neo4j.Message;

public class UpdateNameMessage {
    public UpdateNameMessage(String clientId, Long uuid, String newFileName) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.newFileName = newFileName;
    }

    public String clientId;
    public Long uuid;
    public String newFileName;
}
