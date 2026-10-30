package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.DrawAttackGraphMessage;
import NU.ETWRealTimeDetector.Neo4j.Message.DrawProcessRelationMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageTemplete;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import NU.ETWRealTimeDetector.Process.Process;

public class DrawProcessRelationTask extends BaseTask {
    private Process process;
    private String eventId;

    public DrawProcessRelationTask(Process process, String clientId, String eventId) {
        super(clientId);
        this.process = process;
        this.eventId = eventId;
    }

    @Override
    public void performTask() {
        DrawProcessRelationMessage message = new DrawProcessRelationMessage(this.clientId, Long.valueOf(this.process.getUuid()), this.eventId);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.DrawProcessRelation);
    }
}
