package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.AddProcessNodeMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import NU.ETWRealTimeDetector.Process.Process;

import java.util.Objects;

public class AddProcessNodeTask extends BaseTask {
    private Process process;

    public AddProcessNodeTask(Process process) {
        super(process.getClientId());
        this.process = process;
    }

    @Override
    public void performTask() {
        AddProcessNodeMessage message = new AddProcessNodeMessage(clientId, Long.valueOf(process.getUuid()), process.getProcessId(), process.getStartTime(), process.getEndTime(), process.getProcessName(), process.getCommandLine());

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.AddProcessNode);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof AddProcessNodeTask))
            return false;

        AddProcessNodeTask that = (AddProcessNodeTask) o;

        return Objects.equals(process, that.process);
    }

    @Override
    public int hashCode() {
        return process != null ? process.hashCode() : 0;
    }
}
