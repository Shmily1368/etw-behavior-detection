package NU.ETWRealTimeDetector.Neo4j;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;

public class GraphReceiver extends Thread {
    private static final Logger logger = LoggerFactory.getLogger("graphReceiver");
    private static Logger authorizationLogger = LoggerFactory.getLogger("authorization");
    private final Properties props = new Properties();
    private String bootstrapServers = SysConfig.getString("KafkaBrokerServer");
    private String receiveGraphTopic = SysConfig.getString("ReceiveGraphTopic");
    private String consumerGroup = "GraphReceiver";
    private static boolean sasl = SysConfig.getBoolean("SASL", false);
    KafkaConsumer<String, String> consumer;

    public GraphReceiver() {
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 1);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 30000);
        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 100000);
        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
    }


    @Override
    public void run() {
        // 检查是否有权限
        //KafkaUtil.ensureAuthorization(receiveGraphTopic, "detector", AclOperation.READ);

        // 确认有权限后再开始消费数据
        this.consumer = new KafkaConsumer<>(props);

        this.consumer.subscribe(Arrays.asList(receiveGraphTopic), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                logger.info("Assigned " + partitions);
                for (TopicPartition tp : partitions) {
                    OffsetAndMetadata oam = consumer.committed(tp);
                    if (oam != null) {
                        logger.info("Current offset is " + oam.offset());
                    } else {
                        logger.info("No committed offsets");
                    }
                    //System.out.println("Seeking to " + 0);
                    //consumer.seek(tp, 0);
                }
            }
        });

        while (true) {
            ConsumerRecords<String, String> consumerRecords = consumer.poll(10000);
            if (consumerRecords.isEmpty()) {
                continue;
            }

            consumerRecords.forEach(record -> {
                MessageType messageType;
                try {
                    messageType = MessageType.valueOf(getValueFromHeaders(record.headers(), "type"));
                } catch (Exception e) {
                    logger.error("Missing parameter type offset {}", record.offset());
                    return;
                }

                String clientId = getValueFromHeaders(record.headers(), "clientId");
                if (clientId == null) {
                    logger.error("Missing parameter clientId offset {}", record.offset());
                    return;
                }

                String pid = getValueFromHeaders(record.headers(), "pid");
                if (pid == null) {
                    logger.error("Missing parameter pid offset {}", record.offset());
                    return;
                }

                String processName = getValueFromHeaders(record.headers(), "processName");
                if (processName == null) {
                    logger.error("Missing parameter processName {}", record.offset());
                    return;
                }

                String uuid = getValueFromHeaders(record.headers(), "uuid");
                if (uuid == null) {
                    logger.error("Missing parameter uuid offset {}", record.offset());
                    return;
                }

                logger.info("graph offset {} type {} content {}", record.offset(), messageType.name(), record.value());

                switch (messageType) {
                    case DrawAttackGraph:
                        String eventId = getValueFromHeaders(record.headers(), "eventId");
                        if (eventId == null) {
                            logger.warn("DrawAttackGraph missing eventId uuid {} offset {}", uuid, record.offset());
                            return;
                        }
                        saveAttackGraph(clientId, pid, uuid, record.value(), eventId);
                        Reporter.reportAttackGraphToKafka(eventId, messageType.name(), record.value());
                        break;
                    case DrawProcessRelation:
                        eventId = getValueFromHeaders(record.headers(), "eventId");
                        if (eventId == null) {
                            logger.warn("DrawProcessRelation missing eventId uuid {} offset {}", uuid, record.offset());
                            return;
                        }
                        saveProcessRelation(clientId, pid, uuid, record.value(), eventId);
                        //Reporter.reportGraph(clientId, pid, uuid, processName);
                        Reporter.reportAttackGraphToKafka(eventId, messageType.name(), record.value());
                        break;
                    case DrawSensitiveProgramProcessRelation:
                        String sensitiveProgram = getValueFromHeaders(record.headers(), "sensitiveProgram");
                        String subProcessPid = getValueFromHeaders(record.headers(), "subProcessId");
                        String count = getValueFromHeaders(record.headers(), "count");
                        if (sensitiveProgram == null) {
                            logger.error("Missing parameter sensitiveProgram {}", record.offset());
                            return;
                        }
                        if (subProcessPid == null) {
                            logger.error("Missing parameter subProcessId");
                            return;
                        }

                        if (count == null) {
                            logger.error("Missing parameter count");
                            return;
                        }
                        saveSensitiveProgramProcessRelation(clientId, pid, uuid, subProcessPid, record.value());
                        //Reporter.reportSensitiveProgram(clientId, pid, uuid, processName, subProcessPid, sensitiveProgram, count);
                    default:
                        break;
                }
            });
        }
    }

    private void saveAttackGraph(String clientId, String pid, String uuid, String graph, String eventId) {
        String fileName = Reporter.getAttackGraphFileName(clientId, pid, uuid, eventId);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
            bw.write(graph);
        } catch (IOException e) {
            logger.error("save attackGraph error", e);
        }
    }

    private void saveProcessRelation(String clientId, String pid, String uuid, String graph, String eventId) {
        String fileName = Reporter.getProcessRelationFileName(clientId, pid, uuid, eventId);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
            bw.write(graph);
        } catch (IOException e) {
            logger.error("save attackGraph error", e);
        }
    }

    private void saveSensitiveProgramProcessRelation(String clientId, String ppid, String uuid, String pid, String graph) {
        String fileName = Reporter.getSensitiveProgramProcessRelationFileName(clientId, ppid, uuid, pid);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
            bw.write(graph);
        } catch (IOException e) {
            logger.error("save sensitiveProgram process relation error", e);
        }
    }

    private String getValueFromHeaders(Headers headers, String key) {
        Header header = headers.lastHeader(key);
        if (header == null) {
            return null;
        }

        return getHeaderValue(header);
    }

    private String getHeaderValue(Header header) {
        if (header == null) {
            return null;
        }

        try {
            return new String(header.value(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.error("Decoding Header error", e);
            return null;
        }
    }

}
