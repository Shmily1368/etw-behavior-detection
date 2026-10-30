package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * @author weihao dwh@zju.edu.cn
 * @version 1.1
 * @since 1.0
 */
public class KafkaReceiver extends Thread {
    private final Logger logger = LoggerFactory.getLogger("kafka_receiver");
    private Consumer<Long, String> consumer;
    private String detectorID = SysConfig.getString("DetectorID", "detector01");
    private boolean enableSasl = SysConfig.getBoolean("SASL", false);
    private static String topicName = SysConfig.getString("KafkaTopic", "control");

    /**
     * a Map from topic to the corresponding clientId
     */
    private static Map<String, String> topic2clientID = new HashMap<>();

    /**
     * a Map from clientId to the corresponding topic
     */
//    private static Map<String, Map<String, String>> clientID2other = new HashMap<>();

    private static Map<String, String> clientID2topic = new HashMap<>();
    /**
     * a Set which contents all current alive clients' clientId
     */
    private static Set<String> aliveClientId = new HashSet<>();
    private LinkedBlockingQueue<String> commandQueue;

    /**
     * KafkaReceiver Constructor
     *
     * @param bootstrapServers kafka bootstrap server ipAddress:port
     * @param consumerGroup    kafka consumer groupId
     * @param commandQueue
     */
    public KafkaReceiver(String bootstrapServers, String consumerGroup, LinkedBlockingQueue<String> commandQueue) {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 1);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);
        //props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 30000);
        //props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 100000);

        if (true) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
            props.put("ssl.endpoint.identification.algorithm", "");
        }

        this.consumer = new KafkaConsumer<>(props);
        this.consumer.subscribe(Collections.singletonList(topicName), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                logger.info("onPartitionsRevoked");
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                logger.info("onPartitionsAssigned");
                logger.info("Assigned {}", partitions);
            }
        });
        this.commandQueue = commandQueue;
    }

    /**
     * receive messages from kafka
     *
     * @return a List of received messages
     */
    public List<String> receiveMessage() {
        final ConsumerRecords<Long, String> consumerRecords = consumer.poll(1000);
//        consumer.commitAsync();
        List<String> result = new ArrayList<>();
        consumerRecords.forEach(record -> {
            String message = record.value();
            result.add(message);
            logger.info("recv: {}", message);
        });
        return result;
    }

    /**
     * an infinite loop which keeps take messages from kafka
     * 1. parse the received message using Gson
     * 2. check the DetectorID specified in the message, to see if this message applies to this daemon
     * 3. if this message does not apply to this daemon, do nothing.
     * 4. else, check the command type of this message, there are three types of command: Client_Init, Client_Start, Client_Shutdown
     * 5. Client_Init will set up the corresponding relationship between ClientId and KafkaTopic, or, insert one record to clientID2topic and topic2clientID
     * 6. Client_Start indicates one client with the given clientId will begin to send data. Seek for the topic name from clientID2topic, then notify detector to subscribe to that topic
     * 7. Client_Shutdown indicates one client with the given clientId will stop to send data. Notify detector to stop subscribe that topic.
     * 8. Draw_Graph indicates user request detector to draw graph for a process on a client. Notify detector to draw it.
     */
    @Override
    public void run() {
        Gson gson = new Gson();
        while (true) {
            List<String> messages = receiveMessage();
            for (String message : messages) {
                Type type = new TypeToken<Map<String, String>>() {
                }.getType();

                Map<String, String> parsedMessage = new HashMap<>();
                try {
                    parsedMessage = gson.fromJson(message, type);
                } catch (Exception e) {
                    logger.info(e.getMessage());
                    logger.info(message);
                    continue;
                }

                try {
                    String action = parsedMessage.get("CMD");
                    if (detectorID.equals(parsedMessage.get("DetectorID"))) {
                        switch (action) {
                            case "Client_Init": {
                                String kafkaTopic = parsedMessage.get("KafkaTopic");
                                String clientID = parsedMessage.get("ClientID");
                                topic2clientID.put(kafkaTopic, clientID);
                                clientID2topic.put(clientID, kafkaTopic);
                                break;
                            }
                            case "Client_Start": {
                                String clientID = parsedMessage.get("ClientID");
                                String uuid = parsedMessage.get("uuid");
                                String ip = parsedMessage.getOrDefault("ip", "");
                                if (clientID2topic.containsKey(clientID)) {
                                    Integer offset = -2;
                                    if (parsedMessage.containsKey("Offset")) {
                                        boolean flag = false;
                                        try {
                                            Integer.valueOf(parsedMessage.get("Offset"));
                                            flag = true;
                                        } catch (Exception e) {
                                            flag = false;
                                        }
                                        if (flag) {
                                            offset = Integer.valueOf(parsedMessage.get("Offset"));
                                        }
                                    }
                                    Integer honeyPot = Integer.valueOf(parsedMessage.get("Honeypot"));
                                    String kafkaTopic = clientID2topic.get(clientID);
                                    if (!aliveClientId.contains(clientID)) {
                                        aliveClientId.add(clientID);
                                    }
                                    String command = String.format("{action:add, topic:%s, clientID:%s, uuid:%s, ip:%s, offset:%d, honeyPot:%d}", kafkaTopic, clientID, uuid, ip, offset, honeyPot);
                                    commandQueue.put(command);
                                }
                                break;
                            }
                            default:
                                // do nothing
                        }
                    }
                } catch (Exception e) {
                    logger.error("{}", e.getMessage());
                }
            }
        }
    }
}