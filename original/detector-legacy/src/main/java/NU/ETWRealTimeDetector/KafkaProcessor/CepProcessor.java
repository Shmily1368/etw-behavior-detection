package NU.ETWRealTimeDetector.KafkaProcessor;


import NU.ETWRealTimeDetector.KafkaProcessor.Threat.Threat;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Arrays.asList;

public class CepProcessor extends Thread {
    private static final String bootstrapServers = SysConfig.getString("KafkaBrokerServer");
    private static final String consumerGroup = SysConfig.getString("CEPConsumerGroup", "cep");
    private static boolean sasl = SysConfig.getBoolean("SASL", false);
    private static final String clientLogTopic = SysConfig.getString("ClientLogTopic", "client_log");

    private static final Logger logger = LoggerFactory.getLogger("cep");

    private boolean running = true;
    private Consumer<String, String> consumer;
    private ObjectMapper objectMapper = new ObjectMapper();

    public CepProcessor() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        props.put(ConsumerConfig.MAX_PARTITION_FETCH_BYTES_CONFIG, 1048576 * 9);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 3000);

        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        consumer = new KafkaConsumer<>(props);
        Threat.init();
    }

    @SneakyThrows
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
//                         consumer.seek(tp, 0);

                    }
                    //consumer.seekToBeginning(partitions);
                } catch (Exception e) {
                    logger.error("onPartitionAssigned error", e);
                }
            }
        });
        long currentTimeMillis = System.currentTimeMillis();
        ExecutorService es = Executors.newFixedThreadPool(2);
        LinkedBlockingQueue<Map<String, Object>> eventLogQueueOne = new LinkedBlockingQueue<Map<String, Object>>();
        LinkedBlockingQueue<Map<String, Object>> eventLogQueue = new LinkedBlockingQueue<Map<String, Object>>();
        ClientLogDealProcessor clientLogDealProcessor = new ClientLogDealProcessor(eventLogQueue);
        ClientLogDealProcessor clientLogDealProcessorOne = new ClientLogDealProcessor(eventLogQueueOne);
        es.execute(clientLogDealProcessor);
        es.execute(clientLogDealProcessorOne);
        Set<String> set = new HashSet();
        Set<String> setOne = new HashSet();
        AtomicInteger num = new AtomicInteger();
        boolean flag = false;
        while (running) {
            if(eventLogQueue.size()>10000 || eventLogQueueOne.size()>10000){
                consumer.pause(consumer.assignment());
                flag = true;
                logger.info("cep:"+System.currentTimeMillis());
 //               continue;
            }else{
                if(flag) {
                    consumer.resume(consumer.assignment());
                    flag = false;
                }
            }

            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));

            if (records == null || records.isEmpty()) {
                continue;
            }

            records.forEach(record -> {
                num.incrementAndGet();
                if (num.get() % 10000 == 0) {
                    logger.info(System.currentTimeMillis() + "cep:" + num);
                }
                try {
                    String value = record.value();
                    Map<String, Object> map = objectMapper.readValue(value, HashMap.class);

                    if (!map.containsKey("log_name")) {
                        return;
                    }

                    String logName = map.get("log_name").toString();

                    if (!map.containsKey("event")) {
                        return;
                    }

                    if (map.containsKey("alarm_category")) {
                        // 包含这个字段说明是老的结构 ,忽略数据
                        return;
                    }

                    if ("DangerousCommand".equals(logName)) {
                        // 忽略客户端上报的可疑命令事件
                        return;
                    }

                    if (map.getOrDefault("operation_mode", "0").toString().equals("1")) {
                        // 运维日志忽略
                        return;
                    }

                    String uuid = map.get("uuid").toString();
                    if(set.contains(uuid)){
                        eventLogQueue.put(map);
                    }else if(setOne.contains(uuid)) {
                        eventLogQueueOne.put(map);
                    }else{
                        if(set.size()>setOne.size()){
                            setOne.add(uuid);
                            eventLogQueueOne.put(map);
                        }else{
                            set.add(uuid);
                            eventLogQueue.put(map);
                        }
                    }

                } catch (Exception e) {
                    logger.error("cep process error", e);
                }
            });
        }

        if (consumer != null) {
            consumer.close();
         }
       if (es != null) {
           es.shutdown();
         }
        }

}
