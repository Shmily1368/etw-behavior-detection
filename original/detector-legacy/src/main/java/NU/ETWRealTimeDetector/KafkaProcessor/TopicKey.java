package NU.ETWRealTimeDetector.KafkaProcessor;

public class TopicKey {
    public String topicName;
    public String clientID;
    public String uuid;
    public String ip;
    public Integer offset;
    public boolean shouldStop = false;
    public boolean shouldSeekToOffset = false;
    public int failTime = 0;

    public TopicKey(String topicName, Integer offset, String clientID, String uuid, String ip) {
        this(topicName, clientID, uuid, ip);
        this.offset = offset;
        if (offset >= 0) {
            shouldSeekToOffset = true;
        }
    }

    public TopicKey(String topicName, String clientID, String uuid, String ip) {
        this.topicName = topicName;
        this.clientID = clientID;
        this.uuid = uuid;
        this.ip = ip;
    }


    String getClientID() {
        return this.clientID;
    }

    String getTopicName() {
        return this.topicName;
    }

    void setShouldStop(boolean shouldStop) {
        this.shouldStop = shouldStop;
    }

    boolean getShouldStop() {
        return this.shouldStop;
    }

    int getFailTime() {
        return this.failTime;
    }

    void setFailTime(int failTime) {
        this.failTime = failTime;
    }

    void updateOffset(Integer offset) {
        this.offset = offset;
        shouldSeekToOffset = true;
    }

    void hasBeenSeekToOffset() {
        shouldSeekToOffset = false;
    }

    @Override
    public String toString() {
        return "TopicKey{" +
                "topicName='" + topicName + '\'' +
                ", clientID='" + clientID + '\'' +
                ", offset=" + offset +
                ", shouldStop=" + shouldStop +
                ", shouldSeekToOffset=" + shouldSeekToOffset +
                ", failTime=" + failTime +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TopicKey that = (TopicKey) o;

        if (topicName != null ? !topicName.equals(that.topicName) : that.topicName != null) return false;
        return clientID != null ? clientID.equals(that.clientID) : that.clientID == null;
    }

    @Override
    public int hashCode() {
        int result = topicName != null ? topicName.hashCode() : 0;
        result = 31 * result + (clientID != null ? clientID.hashCode() : 0);
        return result;
    }
}
