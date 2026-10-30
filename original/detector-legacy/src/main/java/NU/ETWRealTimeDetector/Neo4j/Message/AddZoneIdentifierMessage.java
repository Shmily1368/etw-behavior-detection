package NU.ETWRealTimeDetector.Neo4j.Message;

public class AddZoneIdentifierMessage {
    public String clientId;
    public Long uuid;
    public Integer zoneId;
    public String referrerUrl;
    public String hostUrl;
    public String fileName;

    public AddZoneIdentifierMessage(String clientId, Long uuid, Integer zoneId, String referrerUrl, String hostUrl, String fileName) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.zoneId = zoneId;
        this.referrerUrl = referrerUrl;
        this.hostUrl = hostUrl;
        this.fileName = fileName;
    }
}
