package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.AddZoneIdentifierMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import com.google.common.base.Objects;

public class AddZoneIdentifierTask extends BaseTask {
    Long uuid;
    Integer zoneId;
    String referrerUrl;
    String hostUrl;
    String fileName;

    public AddZoneIdentifierTask(String clentId, Long uuid, Integer zoneId, String referrerUrl, String hostUrl, String fileName) {
        super(clentId);
        this.uuid = uuid;
        this.zoneId = zoneId;
        this.referrerUrl = referrerUrl;
        this.hostUrl = hostUrl;
        this.fileName = fileName;
    }

    @Override
    public void performTask() {
        AddZoneIdentifierMessage message = new AddZoneIdentifierMessage(clientId, uuid, zoneId, referrerUrl, hostUrl, fileName);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddZoneIdentifier);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AddZoneIdentifierTask that = (AddZoneIdentifierTask) o;
        return Objects.equal(uuid, that.uuid) &&
                Objects.equal(zoneId, that.zoneId) &&
                Objects.equal(referrerUrl, that.referrerUrl) &&
                Objects.equal(hostUrl, that.hostUrl) &&
                Objects.equal(fileName, that.fileName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(uuid, zoneId, referrerUrl, hostUrl, fileName);
    }
}
