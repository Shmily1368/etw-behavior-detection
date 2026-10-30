package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.RemoveFileNodeMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

public class RemoveFileNodeTask extends BaseTask {
    Long uuid;

    public RemoveFileNodeTask(String clientId, Long uuid) {
        super(clientId);
        this.uuid = uuid;
    }

    @Override
    public void performTask() {
        RemoveFileNodeMessage message = new RemoveFileNodeMessage(clientId, uuid);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.RemoveFileNode);
    }
}
