package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.AddFileNodeMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

import java.util.Objects;

public class AddFileNodeTask extends BaseTask {
    Long uuid;
    String filePath;

    public AddFileNodeTask(String clientId, Long uuid, String filePath) {
        super(clientId);
        this.uuid = uuid;
        this.filePath = filePath;
    }

    @Override
    public void performTask() {

        AddFileNodeMessage message = new AddFileNodeMessage(clientId, uuid, filePath);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddFileNode);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AddFileNodeTask that = (AddFileNodeTask) o;
        return uuid.equals(that.uuid) &&
                filePath.equals(that.filePath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid, filePath);
    }
}
