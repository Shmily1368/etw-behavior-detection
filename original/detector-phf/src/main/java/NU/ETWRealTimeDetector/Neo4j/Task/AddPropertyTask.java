package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Neo4j.Message.AddPropertyMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

public class AddPropertyTask extends BaseTask {
    private static final Logger logger = LoggerFactory.getLogger(AddPropertyTask.class);
    private Node node;
    private String key;
    private String value;

    public AddPropertyTask(Node node, String key, String value) {
        super(node.getClientId());
        this.node = node;
        this.key = key;
        this.value = value;
    }

    @Override
    public void performTask() {
        AddPropertyMessage message = new AddPropertyMessage(this.clientId, this.node.getUuid(), this.key, this.value);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddProperty);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof AddPropertyTask))
            return false;
        if (!super.equals(o))
            return false;

        AddPropertyTask that = (AddPropertyTask) o;

        if (!Objects.equals(key, that.key))
            return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        int result = node.hashCode();
        result = 31 * result + (key != null ? key.hashCode() : 0);
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }
}
