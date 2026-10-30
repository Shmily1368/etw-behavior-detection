package NU.ETWRealTimeDetector.Neo4j.Message;

public class DeleteNodeRelationMessage {
    public DeleteNodeRelationMessage(String clientId, Long fromNodeUuid, Long toNodeUuid, String eventTypeName) {
        this.clientId = clientId;
        this.fromNodeUuid = fromNodeUuid;
        this.toNodeUuid = toNodeUuid;
        this.eventTypeName = eventTypeName;
    }

    public String clientId;
    public Long fromNodeUuid;
    public Long toNodeUuid;
    public String eventTypeName;
}
