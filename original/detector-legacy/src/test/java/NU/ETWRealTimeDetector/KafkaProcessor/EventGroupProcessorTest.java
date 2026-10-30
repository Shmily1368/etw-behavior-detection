package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.KafkaProcessor.Threat.Threat;
import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

public class EventGroupProcessorTest {

    EventGroupProcessor eventGroupProcessor;

    @Before
    public void setup() {
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("EventConsumerGroup", "event_test");
        SysConfig.setString("ClientLogTopic", "client_log");
        SysConfig.setString("ElasticSearch", "127.0.0.1:9200");
        SysConfig.setString("EventTopic", "event2");
        SysConfig.setString("CenterUrl", "http://127.0.0.1:8899");
        SysConfig.setString("RedisHost", "127.0.0.1");
        SysConfig.setInteger("RedisPort", 6379);
        SysConfig.setBoolean("SASL", true);
        SysConfig.setString("url", "127.0.0.1:3306");
        SysConfig.setString("username", "root");
        SysConfig.setString("password", "");
        eventGroupProcessor = new EventGroupProcessor();
    }

    @Test

    public void run() {
        eventGroupProcessor.run();
    }
}