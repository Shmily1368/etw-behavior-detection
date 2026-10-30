package NU.ETWRealTimeDetector.Main;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.KafkaProcessor.ReceiverManager;
import NU.ETWRealTimeDetector.KafkaProcessor.TopicInfo;
import NU.ETWRealTimeDetector.SysConfig;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class SingleTopicMain {
    public static void main(String[] args) throws IOException {
        CompilationConfig.DEBUG = true;
        SysConfig.load("DebugConfig.xml");
        SysConfig.setInteger("ProcessRetentionTime", 1);
        SysConfig.setInteger("ProcessorBufferSize", 100);
        String brokerServer = SysConfig.getString("KafkaBrokerServer", "127.0.0.1:9092");
        String consumerGroup = SysConfig.getString("KafkaConsumerGroup", "testGroup1");
        brokerServer = "127.0.0.1:9092";
        consumerGroup = "SingleTopicLocal7";
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("IllustratorTopic", "illustrator_local");

        ReceiverManager receiverManager = new ReceiverManager(brokerServer, consumerGroup);
        Map<String, TopicInfo> topicNameAndClientIdToStart = new HashMap<>();
        for (int i = 0; i < 1; i++) {
            String topicName = "dev_dev_detector04_5";
            topicNameAndClientIdToStart.put(topicName, new TopicInfo(topicName, "", "", topicName, 0, 0));
        }
        receiverManager.addTopics(topicNameAndClientIdToStart.values().stream().collect(Collectors.toSet()));
    }
}
