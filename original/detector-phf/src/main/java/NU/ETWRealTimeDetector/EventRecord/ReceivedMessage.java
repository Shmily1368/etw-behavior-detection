package NU.ETWRealTimeDetector.EventRecord;

public class ReceivedMessage {
    private byte[] value;
    private String clientID;
    private String uuid;
    private String ip;

    public ReceivedMessage(byte[] value, String clientID, String uuid, String ip) {
        this.value = value;
        this.clientID = clientID;
        this.uuid = uuid;
        this.ip = ip;
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }

    public String getClientID() {
        return clientID;
    }

    public String getUuid() {
        return uuid;
    }

    public String getIp() {
        return ip;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }
}
