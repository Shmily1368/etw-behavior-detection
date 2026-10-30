package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.UpdateNameMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

import java.util.Objects;

public class UpdateNameTask extends BaseTask {

    private long uuid;
    private String newFileName;

    public UpdateNameTask(String clientId, long uuid, String newFileName) {
        super(clientId);
        this.uuid = uuid;
        this.newFileName = newFileName;
    }

    @Override
    public void performTask() {
        UpdateNameMessage message = new UpdateNameMessage(this.clientId, this.uuid, this.newFileName);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.UpdateName);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof UpdateNameTask))
            return false;

        UpdateNameTask that = (UpdateNameTask) o;

        if (uuid != that.uuid)
            return false;
        return Objects.equals(newFileName, that.newFileName);
    }

    @Override
    public int hashCode() {
        int result = (int) (uuid ^ (uuid >>> 32));
        result = 31 * result + (newFileName != null ? newFileName.hashCode() : 0);
        return result;
    }
}
