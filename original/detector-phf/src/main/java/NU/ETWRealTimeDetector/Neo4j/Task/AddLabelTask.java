package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Neo4j.Message.AddLabelMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import com.google.common.base.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;

public class AddLabelTask extends AddNodeRelationTask {
    private static final Logger logger = LoggerFactory.getLogger(AddLabelTask.class);
    private Long fromUuid;
    private Long toUuid;
    private LabelType fromLabel;
    private LabelType toLabel;
    private HashMap<String, String> extend = new HashMap<>();

    public AddLabelTask(String clientId, Node fromNode, Node toNode, LabelType fromLabel, LabelType toLabel, EventType eventType, long timestamp, HashMap<String, String> extend) {
        super(clientId, fromNode, toNode, eventType, timestamp);
        this.fromUuid = fromNode.getUuid();
        this.toUuid = toNode.getUuid();
        this.fromLabel = fromLabel;
        this.toLabel = toLabel;
        this.extend = extend;
    }

    public AddLabelTask(String clientId, Node fromNode, Node toNode, LabelType fromLabel, LabelType toLabel, EventType eventType, long timestamp) {
        super(clientId, fromNode, toNode, eventType, timestamp);
        this.fromUuid = fromNode.getUuid();
        this.toUuid = toNode.getUuid();
        this.fromLabel = fromLabel;
        this.toLabel = toLabel;
    }

    @Override
    public void performTask() {

        AddLabelMessage message = new AddLabelMessage(clientId, fromUuid, toUuid, this.fromLabel.name(), this.toLabel.name(), eventType, timestamp, extend);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddLabel);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AddLabelTask that = (AddLabelTask) o;
        return Objects.equal(fromUuid, that.fromUuid) &&
                Objects.equal(toUuid, that.toUuid) &&
                fromLabel == that.fromLabel &&
                toLabel == that.toLabel &&
                Objects.equal(extend, that.extend);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), fromUuid, toUuid, fromLabel, toLabel, extend);
    }

}
