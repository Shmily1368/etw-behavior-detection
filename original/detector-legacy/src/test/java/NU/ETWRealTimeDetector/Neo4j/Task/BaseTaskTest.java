package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.Neo4j.MessageType;
import org.junit.Test;

import static org.junit.Assert.*;

public class BaseTaskTest {

    @Test
    public void getIntBytes() {
        MessageType messageType = MessageType.UpdateProcessNode;
        byte[] bytes = BaseTask.getIntBytes(messageType.ordinal());
        MessageType messageType2 = MessageType.values()[BaseTask.byte2Int(bytes)];
        assertEquals(messageType, messageType2);
    }

    @Test
    public void byte2Int() {

    }
}