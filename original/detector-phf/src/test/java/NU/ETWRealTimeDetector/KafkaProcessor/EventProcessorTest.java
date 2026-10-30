package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import NU.ETWRealTimeDetector.elasticsearch.EventStore;
import com.alibaba.fastjson.JSONObject;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import static java.util.Arrays.asList;


public class EventProcessorTest {
    EventProcessor processor;

    @Before
    public void setup() {
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("EventConsumerGroup", "event");
        SysConfig.setString("EventTopic", "event");
        SysConfig.setString("ElasticSearch", "127.0.0.1:9200");
        SysConfig.setBoolean("SASL", true);
        processor = new EventProcessor();
    }

    @Test
    public void testEventProcessor() {
        processor.run();
    }

    @Test
    public void testUuid() {
        String id = "1";
        String uuid = UUID.nameUUIDFromBytes(id.getBytes()).toString();
        System.out.println(uuid);
    }

    @Test
    public void testJson() {
        String event = "{\"policy_id\":0,\"log_name\":\"ExsitingMalware\",\"level\":2,\"os_version\":\"Windows\",\"ip_address\":\"\",\"source\":\"EDR\",\"event_category\":\"Malicious\",\"uuid\":\"44d1917fdf8da0edf2cb2b7cd26c5aa7\",\"mac\":\"\",\"result\":0,\"log_category\":\"Process\",\"attck_techniques\":\"\",\"os_type\":1,\"arguments\":{\"parent_process_id\":4076,\"process_id\":1904,\"sha256\":\"\",\"work_directory\":\"\",\"attack_graph\":\"\",\"parent_process_name\":\"C:\\\\Windows\\\\explorer.exe\",\"parent_process_user\":\"\",\"label\":\"PT1,PT16,PT8,PT3,PT18\",\"closed_time\":0,\"parent_process_commandline\":\"C:\\\\Windows\\\\Explorer.EXE\",\"network_info\":\"[{\\\"TimeStamp\\\":\\\"1611903178868\\\",\\\"IP\\\":\\\"127.0.0.1\\\"}]\",\"process_commandline\":\"\\\"C:\\\\Users\\\\shifeng\\\\Desktop\\\\Rat\\\\Babylon 1.6.0.0\\\\55.exe\\\" \",\"update_time\":1611903247580,\"process_name\":\"55.exe\",\"process_uuid\":\"4177a1dd-f26f-3ed0-93cf-d8785056e418\",\"parent_process_uuid\":\"ae78ea79-0f4b-3b43-8747-ca1bbc230896\",\"process_path\":\"C:\\\\Users\\\\shifeng\\\\Desktop\\\\Rat\\\\Babylon 1.6.0.0\\\\55.exe\",\"parent_process_path\":\"\",\"parent_process_md5\":\"\",\"process_tree\":\"\",\"md5\":\"8BCB3849E3BACEA8C833D5D1BCF74075\"},\"id\":\"4177a1dd-f26f-3ed0-93cf-d8785056e418\",\"operating\":\"\",\"terminate\":1,\"event\":true,\"behavior\":1,\"user\":\"\",\"attck_tactics\":\"\",\"host_name\":\"\",\"timestamp\":1611903247580}";
        JSONObject object = JSONObject.parseObject(event);
        if (!object.containsKey("status")) {
            object.put("status", 0);
        }

        String json = object.toJSONString();
        System.out.println(json);

    }

    @Test
    public void kafkaTest() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "127.0.0.1:9092");
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "2");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        //props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 100);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        //props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 30000);
        //props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 100000);

        props.put("security.protocol", "SASL_PLAINTEXT");
        props.put("sasl.mechanism", "PLAIN");
        props.put("sasl.jaas.config", KafkaUtil.getCypher());
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props);

        consumer.subscribe(asList("test"), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                System.out.println(("onPartitionRevoked."));
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                System.out.println(("onPartitionAssigned."));
                System.out.println(String.format("Assigned %s", partitions));
                try {
                    Map<TopicPartition, Long> topicsEndOffset = consumer.endOffsets(partitions);
                    for (TopicPartition tp : partitions) {
                        String topic = tp.topic();
                        Long endOffset = topicsEndOffset.get(tp);

                        OffsetAndMetadata oam = consumer.committed(tp);
                        long committedOffset = 0;
                        if (oam != null) {
                            committedOffset = oam.offset();
                            System.out.println(String.format("%s EndOffset is %d Current offset is %d", topic, endOffset, oam.offset()));
                            ;
                        } else {
                            System.out.println(String.format("%s EndOffset is %d No committed offsets", topic, endOffset));
                        }

                        // 更新到指定的topic
                        // consumer.seek(tp, 0);

                    }
                    consumer.seekToBeginning(partitions);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        while (true) {
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));
            if (records == null || records.isEmpty()) {
                continue;
            }

            records.forEach(record -> {
                try {
                    System.out.println(String.format("message offset :%d value:%s ", record.offset(), record.value()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }
}

