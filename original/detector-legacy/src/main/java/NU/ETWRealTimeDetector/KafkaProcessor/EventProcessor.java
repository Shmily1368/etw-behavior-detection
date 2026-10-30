package NU.ETWRealTimeDetector.KafkaProcessor;


import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import NU.ETWRealTimeDetector.elasticsearch.EventStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.asList;

public class EventProcessor extends Thread {
    private static final String bootstrapServers = SysConfig.getString("KafkaBrokerServer");
    private static final String eventConsumerGroup = SysConfig.getString("EventConsumerGroup");
    private static final String eventTopic = SysConfig.getString("EventTopic");
    private static final Logger logger = LoggerFactory.getLogger("event");
    private static boolean sasl = SysConfig.getBoolean("SASL", false);
    private static boolean eventDuplicate = SysConfig.getBoolean("EventDuplicate", true);


    private static Cache<String, Long> logIdCache = Caffeine.newBuilder()
            .initialCapacity(1000)
            .maximumSize(50000)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();

    private KafkaConsumer<String, String> consumer;
    private boolean running = true;
    private ObjectMapper objectMapper = new ObjectMapper();

    public EventProcessor() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, eventConsumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        //props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 100);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        //props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 30000);
        //props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 100000);

        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        consumer = new KafkaConsumer<>(props);
    }

    @Override
    public void run() {
        logger.info("event processor start.");
        consumer.subscribe(asList(eventTopic), new ConsumerRebalanceListener() {
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
                    logger.info("something offset {} value {}", record.offset(), value);
                    Map<String, Object> map = objectMapper.readValue(value, HashMap.class);

                    String logName = (String)map.getOrDefault("log_name", "");

                    String logId = map.getOrDefault("id", "").toString();
                    String uuid = map.getOrDefault("uuid", "").toString();
                    Long timestamp = (Long) map.getOrDefault("timestamp", 0L);
                    boolean isWindowsEdrGraph = map.containsKey("jsonGraph");

                    // edr 溯源图数据没有 logId uuid timestamp 这三个字段
                    if (!isWindowsEdrGraph) {
                        if (!ObjectUtils.allNotNull(logId, uuid, timestamp)) {
                            return;
                        }
                        if (timestamp.equals(0L)) {
                            return;
                        }
                    }

                    if (checkOperationMode(map)) {
                        return;
                    }

                    if (value.contains("DrawAttackGraph")) {
                        EventStore.getInstance().saveGraph(value);
                    } else if (value.contains("DrawProcessRelation")) {
                        EventStore.getInstance().saveGraph(value);
                    } else if (value.contains("Malicious")) {
                        EventStore.getInstance().saveWindowsEDREvent(value);
                    } else {
                        // 判断事件是否重复
                        if (eventDuplicate && exist(logId, uuid, timestamp)) {
                            logger.info("Duplicate events {}", value);
                            return;
                        }
                        EventStore.getInstance().saveEvent(value);
                    }
                    logger.info("message:{}", record.value());
                } catch (Exception e) {
                    logger.error("error", e);
                }
            });
        }

        consumer.close();
    }

    public static boolean checkOperationMode(Map<String, Object> map) {
        String logName = (String) map.getOrDefault("log_name", "");
        boolean isOperationMode = "1".equals(map.getOrDefault("operation_mode", "0").toString());

        // 如果是病毒防护
        if ("AntivirusProtection".equals(logName)) {
            // 运维模式下非手动扫描不产生事件
            if (isOperationMode) {
                Map<String, Object> arguments = (Map<String, Object>) map.get("arguments");
                if (!arguments.containsKey("scan_type")) {
                    return true;
                }
                String scanType = arguments.get("scan_type").toString();
                return !"1".equals(scanType);
            }
        } else {
            // 运维日志忽略
            return isOperationMode;
        }
        return false;
    }

    public static boolean exist(String logId, String uuid, Long timestamp) {
        String cacheKey = String.format("%s_%s", logId, uuid);
        Long cacheValue = logIdCache.getIfPresent(cacheKey);
        if (cacheValue == null) {
            logIdCache.put(cacheKey, timestamp);
            return false;
        }
        return true;
    }
}
