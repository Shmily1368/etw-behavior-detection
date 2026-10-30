package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.KafkaProcessor.Threat.Threat;
import NU.ETWRealTimeDetector.KafkaProcessor.Virus.DefenseWay;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import org.junit.Before;
import org.junit.Test;
import redis.clients.jedis.Jedis;

import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

public class ClientLogProcessorTest {
    ClientLogProcessor clientLogProcessor;
    private static LinkedBlockingQueue<DefenseWay> defenseWay = new LinkedBlockingQueue<>();


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
        clientLogProcessor = new ClientLogProcessor(defenseWay);
    }

    @Test
    public void run() {
        ClientLogProcessor clientLogProcessor = new ClientLogProcessor(defenseWay);
        clientLogProcessor.run();
    }
}