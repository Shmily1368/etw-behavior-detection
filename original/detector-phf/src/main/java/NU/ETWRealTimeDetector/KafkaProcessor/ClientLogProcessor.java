package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.KafkaProcessor.Virus.AntivirusProcessor;
import NU.ETWRealTimeDetector.KafkaProcessor.Virus.DefenseWay;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

import static java.util.Arrays.asList;

public class ClientLogProcessor extends Thread {
    private static final String lockEventTopic = SysConfig.getString("LockEventTopic", "lock_event");
    private static final String eventTopic = SysConfig.getString("EventTopic", "event");
    private static final String bootstrapServers = SysConfig.getString("KafkaBrokerServer");
    private static final String consumerGroup = SysConfig.getString("EventLogGroup");
    private static final String clientLogTopic = SysConfig.getString("ClientLogTopic", "client_log");
    private static final Logger logger = LoggerFactory.getLogger("client_log");
    private static boolean sasl = SysConfig.getBoolean("SASL", false);
    private List<String> lockEventTypes = new ArrayList<>();

    private Consumer<String, String> consumer;
    private boolean running = true;

    private ObjectMapper objectMapper = new ObjectMapper();

    private final LinkedBlockingQueue<DefenseWay> upstream;

    public ClientLogProcessor(LinkedBlockingQueue<DefenseWay> upstream) {
        this.upstream = upstream;
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        //props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        //props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 100);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        //props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 30000);
        //props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 100000);
        props.put(ConsumerConfig.MAX_PARTITION_FETCH_BYTES_CONFIG, 1048576 * 9);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 3000);
        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        consumer = new KafkaConsumer<>(props);

        lockEventTypes.add("Mining");
        lockEventTypes.add("PortScan");
        lockEventTypes.add("HoneyPort");
        lockEventTypes.add("ReverseShell");
        lockEventTypes.add("ClientUnlockIP");
        lockEventTypes.add("Crack");
    }

    @Override
    public void run() {
        consumer.subscribe(asList(clientLogTopic), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                logger.warn("onPartitionRevoked.");
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                logger.info("onPartitionAssigned.");
                logger.info("Assigned {}", partitions);
                try {
                    Map<TopicPartition, Long> topicsEndOffset = consumer.endOffsets(partitions);
                    for (TopicPartition tp : partitions) {
                        String topic = tp.topic();
                        Long endOffset = topicsEndOffset.get(tp);

                        OffsetAndMetadata oam = consumer.committed(tp);
                        long committedOffset = 0;
                        if (oam != null) {
                            committedOffset = oam.offset();
                            logger.info("{} EndOffset is {} Current offset is {}", topic, endOffset, oam.offset());
                        } else {
                            logger.info("{} EndOffset is {} No committed offsets", topic, endOffset);
                        }

                        // 更新到指定的topic
                        // consumer.seek(tp, 0);

                    }
                    //consumer.seekToBeginning(partitions);
                } catch (Exception e) {
                    logger.error("onPartitionAssigned error", e);
                }
            }
        });

        while (running) {
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));
            if (records == null || records.isEmpty()) {
                continue;
            }
            records.forEach(record -> {
                try {
                    String value = record.value();

                    Map<String, Object> map = objectMapper.readValue(value, HashMap.class);

                    if (!map.containsKey("log_name")) {
                        return;
                    }

                    String logName = map.get("log_name").toString();

                    // 如果日志是病毒防护，则需要判断它是否是防御日志，防御日志不生成事件
                    if (AntivirusProcessor.process(upstream, map)) {
                        return;
                    }

                    if (!map.containsKey("event")) {
                        return;
                    }

                    if (map.containsKey("alarm_category")) {
                        // 包含这个字段说明是老的结构 ,忽略数据
                        return;
                    }

                    Object event = map.get("event");

                    Boolean isEvent = Boolean.valueOf(event.toString());
                    if (logName.equals("DangerousCommand")) {
                        // 忽略客户端上报的可疑命令事件
                        return;
                    }

                    if (isLockEvent(logName)) {
                        Reporter.reportEventToKafka(lockEventTopic, value);
                    }

                    if (!isEvent) {
                        // event 字段 事件为true 日志为false,只把事件挑出来转发到event topic 写入es,日志忽略
                        return;
                    }

                    if (EventProcessor.checkOperationMode(map)) {
                        return;
                    }

                    value = EventGroupProcessor.process(map);
                    Reporter.reportEventToKafka(eventTopic, value);
                    logger.info("receive event on offset {}", record.offset());
                } catch (Exception e) {
                    logger.error("error offset " + record.offset(), e);
                }
            });
        }

        consumer.close();

    }

    private boolean isLockEvent(String logName) {
        return lockEventTypes.stream().anyMatch(s -> s.equals(logName));
    }
}
