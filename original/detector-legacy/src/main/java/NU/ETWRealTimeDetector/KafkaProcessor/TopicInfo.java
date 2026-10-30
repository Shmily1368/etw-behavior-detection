package NU.ETWRealTimeDetector.KafkaProcessor;


import java.util.Objects;

public class TopicInfo {
    private String clientId;
    private String uuid;
    private String ip;
    private String topicName;

    public void setOffset(Integer offset) {
        this.offset = offset;
    }

    public void setHoneyPot(Integer honeyPot) {
        this.honeyPot = honeyPot;
    }

    private Integer offset;
    private Integer honeyPot;

    public TopicInfo(String clientId, String uuid, String ip, String topicName, Integer offset, Integer honeyPot) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.ip = ip;
        this.topicName = topicName;
        this.offset = offset;
        this.honeyPot = honeyPot;
    }

    public String getClientId() {
        return clientId;
    }

    public String getUuid() {
        return uuid;
    }

    public String getIp(){
        return ip;
    }

    public String getTopicName() {
        return topicName;
    }

    public Integer getOffset() {
        return offset;
    }

    public Integer getHoneyPot() {
        return honeyPot;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TopicInfo topicInfo = (TopicInfo) o;
        return clientId.equals(topicInfo.clientId) &&
                topicName.equals(topicInfo.topicName);
        //honeyPot.equals(topicInfo.honeyPot) &&
        //offset.equals(topicInfo.offset)
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, topicName);
    }
}
