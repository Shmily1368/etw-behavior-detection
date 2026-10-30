package NU.ETWRealTimeDetector.Neo4j;

import java.util.HashMap;

public class MessageTemplete {
    public String clientId;
    public MessageType messageType;
    public HashMap<String, Object> data = new HashMap<>();

    public MessageTemplete(String clientId, MessageType messageType) {
        this.clientId = clientId;
        this.messageType = messageType;
    }
}
