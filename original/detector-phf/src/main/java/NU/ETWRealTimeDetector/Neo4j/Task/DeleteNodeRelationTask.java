package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Neo4j.Message.DeleteNodeRelationMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;

import java.util.Objects;

public class DeleteNodeRelationTask extends BaseTask {
    protected Node fromNode;
    protected Node toNode;
    protected String eventType;

    public DeleteNodeRelationTask(String clientId, Node fromNode, Node toNode, EventType eventType) {
        super(clientId);
        this.fromNode = fromNode;
        this.toNode = toNode;
        this.eventType = eventType != null ? eventType.name() : "";
    }

    @Override
    public void performTask() {
        DeleteNodeRelationMessage message = new DeleteNodeRelationMessage(this.clientId, this.fromNode.getUuid(), this.toNode.getUuid(), this.eventType);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.DeleteNodeRelation);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof DeleteNodeRelationTask))
            return false;

        DeleteNodeRelationTask that = (DeleteNodeRelationTask) o;

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
