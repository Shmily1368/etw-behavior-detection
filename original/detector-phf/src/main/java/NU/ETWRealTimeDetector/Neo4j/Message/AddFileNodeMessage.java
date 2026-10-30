package NU.ETWRealTimeDetector.Neo4j.Message;

public class AddFileNodeMessage {
    public String clientId;
    public Long uuid;
    public String name;

    public AddFileNodeMessage(String clientId, Long uuid, String name) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.name = name;
    }
}
