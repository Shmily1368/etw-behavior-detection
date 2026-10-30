package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.KafkaProcessor.Threat.Threat;
import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class CepProcessorTest {

    CepProcessor cepProcessor;

    @Before
    public void setup() {
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("CEPConsumerGroup", "cep_test1");
        SysConfig.setString("EventConsumerGroup", "event_test1");
        SysConfig.setString("ClientLogTopic", "client_log");
        SysConfig.setString("ElasticSearch", "127.0.0.1:9200");
        SysConfig.setString("EventTopic", "event2");
        SysConfig.setString("CenterUrl", "http://127.0.0.1:8899");
        SysConfig.setString("TrustIpListApi", "/api/policy/rule/trust/ip");
        SysConfig.setString("RedisHost", "127.0.0.1");
        SysConfig.setInteger("RedisPort", 6379);
        SysConfig.setBoolean("SASL", true);
        Threat.init();
        cepProcessor = new CepProcessor();
    }

    @Test

    public void run() {
        cepProcessor.run();

//        Map<String, Object> args = new HashMap<>();
//        args.put("remote_ip", "148.66.138.116");
//        args.put("process_name", "tersts");
//
//        Map<String, Object> map = new HashMap<>();
//        map.put("id", "dsafdsaf");
//        map.put("arguments", args);
//
//        Threat.check(map);
    }
}