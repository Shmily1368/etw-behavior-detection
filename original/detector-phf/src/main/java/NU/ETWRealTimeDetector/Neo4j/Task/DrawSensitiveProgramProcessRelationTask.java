package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.DrawSensitiveProgramProcessRelationMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import NU.ETWRealTimeDetector.Process.Process;

import java.util.HashMap;

public class DrawSensitiveProgramProcessRelationTask extends BaseTask {
    private Process process;
    private String cmds;
    private HashMap<String, String> extend;

    public DrawSensitiveProgramProcessRelationTask(Process process, String clientId, String cmds, HashMap<String, String> extend) {
        super(clientId);
        this.process = process;
        this.cmds = cmds;
        this.extend = extend;
    }

    @Override
    public void performTask() {
        DrawSensitiveProgramProcessRelationMessage message = new DrawSensitiveProgramProcessRelationMessage(this.clientId, Long.valueOf(this.process.getUuid()), cmds, extend);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.DrawSensitiveProgramProcessRelation);
    }
}
