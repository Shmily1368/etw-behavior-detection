package NU.ETWRealTimeDetector.alarm;

import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

public class AlarmProcessorTest {
    AlarmProcessor alarmProcessor;

    @Before
    public void init() {
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("EventConsumerGroup", "event");
        SysConfig.setString("EventTopic", "event");
        SysConfig.setString("AlarmTopic", "alarm");
        SysConfig.setString("AlarmConsumerGroup", "alarm");
        SysConfig.setString("ElasticSearch", "127.0.0.1:9200");
        SysConfig.setBoolean("SASL", true);
        alarmProcessor = new AlarmProcessor();
    }

    @Test
    public void run() {
        alarmProcessor.run();
    }
}