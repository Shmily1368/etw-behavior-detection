package NU.ETWRealTimeDetector.Neo4j.Task;


import NU.ETWRealTimeDetector.Neo4j.Message.UpdateProcessNodeMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

import java.util.Objects;

public class UpdateProcessNodeTask extends BaseTask {
    private long uuid;
    private String propertyName;
    private Object propertyValue;

    public UpdateProcessNodeTask(String clientId, long uuid, String propertyName, Object propertyValue) {
        super(clientId);
        this.uuid = uuid;
        this.propertyName = propertyName;
        this.propertyValue = propertyValue;
    }

    @Override
    public void performTask() {
        UpdateProcessNodeMessage message = new UpdateProcessNodeMessage(this.clientId, this.uuid, this.propertyName, this.propertyValue.toString());
        _output.reset();
        _kryo.writeObject(_output, message);
        send(_output.toBytes(), MessageType.UpdateProcessNode);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof UpdateProcessNodeTask))
            return false;

        UpdateProcessNodeTask that = (UpdateProcessNodeTask) o;

        if (uuid != that.uuid)
            return false;
        if (!Objects.equals(propertyName, that.propertyName))
            return false;
        return Objects.equals(propertyValue, that.propertyValue);
    }

    @Override
    public int hashCode() {
        int result = (int) (uuid ^ (uuid >>> 32));
        result = 31 * result + (propertyName != null ? propertyName.hashCode() : 0);
        result = 31 * result + (propertyValue != null ? propertyValue.hashCode() : 0);
        return result;
    }
}
