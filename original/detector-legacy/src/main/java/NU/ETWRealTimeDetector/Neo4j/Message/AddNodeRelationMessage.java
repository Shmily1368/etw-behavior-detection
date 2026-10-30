package NU.ETWRealTimeDetector.Neo4j.Message;

public class AddNodeRelationMessage {
    public AddNodeRelationMessage(String clientId, Long fromNodeUuid, Long toNodeUuid, String eventTypeName, Long timeStamp) {
        this.clientId = clientId;
        this.fromNodeUuid = fromNodeUuid;
        this.toNodeUuid = toNodeUuid;
        this.eventTypeName = eventTypeName;
        this.timeStamp = timeStamp;
    }

    public String clientId;
    public Long fromNodeUuid;
    public Long toNodeUuid;
    public String eventTypeName;
    public Long timeStamp;
}
