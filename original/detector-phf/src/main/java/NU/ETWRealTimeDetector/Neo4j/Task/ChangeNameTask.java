package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.Message.ChangeNameMessage;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import com.google.common.base.Objects;

public class ChangeNameTask extends BaseTask {
    public static final String separationCharacter = "\\n";

    private long oldFileNodeUuid;
    private long newFileNodeUuid;
    private String newFileName;

    public ChangeNameTask(String clientId, long oldFileNodeUuid, long newFileNodeUuid, String newFileName) {
        super(clientId);
        this.oldFileNodeUuid = oldFileNodeUuid;
        this.newFileNodeUuid = newFileNodeUuid;
        this.newFileName = newFileName;
    }

    @Override
    public void performTask() {
        ChangeNameMessage message = new ChangeNameMessage(this.clientId, this.oldFileNodeUuid, this.newFileNodeUuid, this.newFileName);

        _output.reset();
        _kryo.writeObject(_output, message);

        send(_output.toBytes(), MessageType.ChangeName);
    }

    public static void prune(StringBuilder builder) {
        if (count(builder.toString(), separationCharacter) > 3) {
            builder.delete(0, builder.indexOf(separationCharacter) + separationCharacter.length());
        }
    }

    public static int count(String srcStr, String findStr) {
        int count = 0;
        int index = 0;

        while ((index = srcStr.indexOf(findStr, index)) != -1) {
            index = index + findStr.length();
            count++;
        }

        return count;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ChangeNameTask that = (ChangeNameTask) o;
        return oldFileNodeUuid == that.oldFileNodeUuid &&
                newFileNodeUuid == that.newFileNodeUuid &&
                Objects.equal(newFileName, that.newFileName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(oldFileNodeUuid, newFileNodeUuid, newFileName);
    }
}
