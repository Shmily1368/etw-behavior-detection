package NU.ETWRealTimeDetector.EventRecord;

import NU.ETWRealTimeDetector.ETWproto.Etwdata.EventRecords;

public class ProtobufParsedMessage {
    public EventRecords message;
    public String clientID;

    public ProtobufParsedMessage(String clientID, EventRecords message) {
        this.clientID = clientID;
        this.message = message;
    }
}
