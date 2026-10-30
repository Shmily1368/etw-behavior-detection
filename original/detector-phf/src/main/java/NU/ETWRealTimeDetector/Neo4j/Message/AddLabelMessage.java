package NU.ETWRealTimeDetector.Neo4j.Message;

import java.util.HashMap;

public class AddLabelMessage {
    public AddLabelMessage(String clientId, Long fromNodeUuid, Long toNodeUuid, String fromLabelName, String toLabelName, String eventTypeName, Long timeStamp, HashMap<String, String> extend) {
        this.clientId = clientId;
        this.fromNodeUuid = fromNodeUuid;
        this.toNodeUuid = toNodeUuid;
        this.fromLabelName = fromLabelName;
        this.toLabelName = toLabelName;
        this.eventTypeName = eventTypeName;
        this.timeStamp = timeStamp;
        this.extend = extend;
    }

    public String clientId;
    public Long fromNodeUuid;
    public Long toNodeUuid;
    public String fromLabelName;
    public String toLabelName;
    public String eventTypeName;
    public Long timeStamp;
    public HashMap<String, String> extend = new HashMap<>();
}
