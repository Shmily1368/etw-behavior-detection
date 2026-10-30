package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.IPC.TopicController;
import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class ReceiverManagerTest {

    @Before
    public void setconfig() {
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("KafkaConsumerGroup", "testGroup1");
    }

    @Test
    public void addTopics() {
        String brokerServer = SysConfig.getString("KafkaBrokerServer", "127.0.0.1:9092");
        String consumerGroup = SysConfig.getString("KafkaConsumerGroup", "testGroup1");
        ReceiverManager receiverManager = new ReceiverManager(brokerServer, consumerGroup);
        TopicController topicController = new TopicController(receiverManager, null);
        topicController.run();
    }

    @Test
    public void testAddTopics() {
        ReceiverManager receiverManager = new ReceiverManager("", "");
        AtomicInteger counter = new AtomicInteger();
        for (int i = 1; i < 10; i++) {
            Set<TopicInfo> set = new HashSet<>();
            for (int j = 1; j < 10; j++) {
                counter.incrementAndGet();
                set.add(new TopicInfo(String.valueOf(counter.get()), "", "", String.valueOf(counter.get()), -1, 0));
            }
            receiverManager.addTopics(set);
        }
    }
}