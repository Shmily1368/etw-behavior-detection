package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Neo4j.Message.AddNodeRelationMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

import java.util.Objects;

public class AddNodeRelationTask extends BaseTask {
    Node fromNode;
    Node toNode;
    protected String eventType;
    protected long timestamp;

    public AddNodeRelationTask(String clientId, Node fromNode, Node toNode, EventType eventType, long timestamp) {
        super(clientId);
        this.fromNode = fromNode;
        this.toNode = toNode;
        this.eventType = eventType != null ? eventType.name() : "";
        this.timestamp = timestamp;
    }

    @Override
    public void performTask() {
        AddNodeRelationMessage message = new AddNodeRelationMessage(clientId, this.fromNode.getUuid(), this.toNode.getUuid(), this.eventType, this.timestamp);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddNodeRelation);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof AddNodeRelationTask))
            return false;

        AddNodeRelationTask that = (AddNodeRelationTask) o;

        if (!Objects.equals(fromNode, that.fromNode))
            return false;
        if (!Objects.equals(toNode, that.toNode))
            return false;
        return Objects.equals(eventType, that.eventType);
    }

    @Override
    public int hashCode() {
        int result = fromNode != null ? fromNode.hashCode() : 0;
        result = 31 * result + (toNode != null ? toNode.hashCode() : 0);
        result = 31 * result + (eventType != null ? eventType.hashCode() : 0);
        return result;
    }
}
