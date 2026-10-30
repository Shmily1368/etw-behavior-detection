package NU.ETWRealTimeDetector.Neo4j.Message;

public class UpdateProcessNodeMessage {
    public UpdateProcessNodeMessage(String clientId, Long uuid, String propertyName, String propertyValue) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.propertyName = propertyName;
        this.propertyValue = propertyValue;
    }

    public String clientId;
    public Long uuid;
    public String propertyName;
    public String propertyValue;
}
