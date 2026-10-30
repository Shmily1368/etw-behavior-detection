package NU.ETWRealTimeDetector.Neo4j.Message;

public class DrawProcessRelationMessage {
    public DrawProcessRelationMessage(String clientId, Long uuid, String eventId) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.eventId = eventId;
    }

    public String clientId;
    public Long uuid;
    public String eventId;
}
