package NU.ETWRealTimeDetector.Neo4j.Message;

public class AddPropertyMessage {
    public AddPropertyMessage(String clientId, Long uuid, String key, String value) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.key = key;
        this.value = value;
    }

    public String clientId;
    public Long uuid;
    public String key;
    public String value;
}
