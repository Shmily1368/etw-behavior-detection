/*
package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.Cache.TraceCache;
import NU.ETWRealTimeDetector.Cache.TraceKey;
import NU.ETWRealTimeDetector.Cache.WaitingTraceProcessor;
import NU.ETWRealTimeDetector.EventRecord.ProtobufParsedMessage;
import NU.ETWRealTimeDetector.IPC.SocketCommunicator;
import NU.ETWRealTimeDetector.SysConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.LongDeserializer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class ReceiverManager {

    private Set<TopicKey> aliveTopicEntitiesSet = new HashSet<>(100);
    private ConcurrentMap<String, Consumer<Long, byte[]>> topic2consumer = new ConcurrentHashMap<>();
    private ConcurrentMap<Consumer<Long, byte[]>, ConcurrentLinkedQueue<TopicKey>> consumer2topicEntities = new ConcurrentHashMap<>();

    private final Logger logger = LoggerFactory.getLogger(ReceiverManager.class);
    private final boolean seek0 = SysConfig.getBoolean("Seek0", false);
    private final Properties props = new Properties();

    private ConcurrentLinkedQueue<ConcurrentMap<TraceKey, TraceCache>> listOfTraceKey2traceCache = new ConcurrentLinkedQueue<>();
    private SocketCommunicator communicator = SocketCommunicator.getInstance();

    private ExecutorService pool = Executors.newCachedThreadPool();

    public ReceiverManager(String bootstrapServers, String consumerGroup) {
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, LongDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        WaitingTraceProcessor waitingTraceProcessor = new WaitingTraceProcessor(listOfTraceKey2traceCache);
        Thread waitingTraceProcessorThread = new Thread(waitingTraceProcessor);
        waitingTraceProcessorThread.setPriority(10);
        waitingTraceProcessorThread.start();
        logger.info("start wait trace processor");
    }

    public void addReceiveThread(LinkedHashMap<String, String> topicAndClientID) {
        Iterator<Map.Entry<String, String>> iterator = topicAndClientID.entrySet().iterator();
        List<TopicKey> topicEntitiesToStart = new ArrayList<>();
        while (iterator.hasNext()) {
            Map.Entry<String, String> entry = iterator.next();
            TopicKey topicEntity = new TopicKey(entry.getKey(), entry.getValue(), false);
            logger.info("add client {} on topic {}", topicEntity.clientID, topicEntity.topicName);
            // if still alive, set shouldStop to false
            if (aliveTopicEntitiesSet.contains(topicEntity)) {
                aliveTopicEntitiesSet.remove(topicEntity);
                aliveTopicEntitiesSet.add(topicEntity);
                iterator.remove();
            } else {
                topicEntitiesToStart.add(topicEntity);
            }
        }

        // excluded all alive topics, the remain are all dead at this moment
        aliveTopicEntitiesSet.addAll(topicEntitiesToStart);

        boolean foundFreeConsumer = false;

        // find a consumer with has free space
        for (ConcurrentMap.Entry<Consumer<Long, byte[]>, ConcurrentLinkedQueue<TopicKey>> entry : consumer2topicEntities.entrySet()) {
            if (entry.getValue().size() + topicEntitiesToStart.size() <= 10) {
                foundFreeConsumer = true;
                entry.getValue().addAll(topicEntitiesToStart);
                Consumer<Long, byte[]> consumer = entry.getKey();
                List<String> topicNameList = entry.getValue().stream().map(TopicKey::getTopicName).collect(Collectors.toList());
                synchronized (consumer) {
                    changeSubscribedTopics(consumer, topicNameList);
                    consumer.poll(0);
                    for (String topic : topicNameList) {
                        topic2consumer.put(topic, consumer);
                        TopicPartition topicPartition = new TopicPartition(topic, 0);
                        if (seek0) {
                            consumer.seek(topicPartition, 0);
                        }
                    }
                }
                break;
            }
        }

        // if cannot find, create a new consumer
        if (!foundFreeConsumer) {
            ConcurrentLinkedQueue<TopicKey> topicEntities = new ConcurrentLinkedQueue<>();
            topicEntities.addAll(topicEntitiesToStart);
            Consumer<Long, byte[]> consumer = new KafkaConsumer<>(props);
            consumer.subscribe(topicEntities.stream().map(TopicKey::getTopicName).collect(Collectors.toList()));

            for (TopicKey topicEntity : topicEntities) {
                topic2consumer.put(topicEntity.topicName, consumer);
                communicator.sendMessage(String.format("{action:add, clientID:%s}", topicEntity.clientID));
            }

            consumer2topicEntities.put(consumer, topicEntities);

            // bridge between messageReceiver and messageProcessor
            LinkedBlockingQueue<ProtobufParsedMessage> protobufParseMessageQueue = new LinkedBlockingQueue<>();
            ConcurrentMap<TraceKey, TraceCache> traceKey2traceCache = new ConcurrentHashMap<>();
            listOfTraceKey2traceCache.add(traceKey2traceCache);

            Runnable messageReceiver = new MessageReceiver(consumer, protobufParseMessageQueue, topicEntities, aliveTopicEntitiesSet);
            Runnable messageProcessor = new MessageProcessor(protobufParseMessageQueue, traceKey2traceCache);
            pool.execute(messageReceiver);
            pool.execute(messageProcessor);
        }
    }

    public void requestStopTopic(String clientID, String topic) {
        logger.info("request client {} on topic {} to stop", clientID, topic);
        TopicKey topicEntity = new TopicKey(topic, clientID, true);

        if (aliveTopicEntitiesSet.contains(topicEntity)) {
            aliveTopicEntitiesSet.remove(topicEntity);
            aliveTopicEntitiesSet.add(topicEntity);
        }
        if (topic2consumer.containsKey(topic)) {
            Consumer<Long, byte[]> consumer = topic2consumer.get(topic);
            ConcurrentLinkedQueue<TopicKey> queue = consumer2topicEntities.get(consumer);
            queue.remove(topicEntity);
            queue.add(topicEntity);
        }
    }
}
*/
package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.EventRecord.ReceivedMessage;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.LongDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class ReceiverManager {

    private static final int MAX_Client_Per_Proessor = SysConfig.getInteger("MaxClientPerProessor", 50);
    private static final int MAX_Poll_Records = SysConfig.getInteger("MaxPollRecords", 50);
    private final boolean startWaitTraceProcessor = false;
    private static boolean sasl = SysConfig.getBoolean("SASL", false);

    private Set<TopicKey> aliveTopicKeySet = new HashSet<>(100);
    private Map<TopicKey, MessageReceiver> topicKey2MessageReceiver = new HashMap<>();
    private Set<MessageReceiver> messageReceivers = new HashSet<>();

    private final Logger friendlyLogger = LoggerFactory.getLogger("FriendlyLogger");
    private final Logger topicLogger = LoggerFactory.getLogger("topic");
    private final Logger logger = LoggerFactory.getLogger(ReceiverManager.class);
    private final boolean seek0 = SysConfig.getBoolean("Seek0", false);
    private final Properties props = new Properties();
    private ExecutorService pool = Executors.newCachedThreadPool();
    public ReceiverManager(String bootstrapServers, String consumerGroup) {
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, LongDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, MAX_Poll_Records);
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

    public void addTopics(Set<TopicInfo> topicInfos) {
        Iterator<TopicInfo> iterator = topicInfos.iterator();

        List<TopicKey> topicKeysToStart = new ArrayList<>();
        while (iterator.hasNext()) {
            TopicInfo topicInfo = iterator.next();
            TopicKey topicKey = new TopicKey(topicInfo.getTopicName(), topicInfo.getOffset(), topicInfo.getClientId(), topicInfo.getUuid(), topicInfo.getIp());
            // 检查是否有权限消费数据
            /*

            boolean hasPermission = KafkaUtil.checkAuthorization(topicInfo.getTopicName(), "detector", AclOperation.READ);
            topicLogger.info("{} authorization: {}", topicInfo.getTopicName(), hasPermission);
            if (!hasPermission) {
                continue;
            }
             */

            friendlyLogger.info("开始接收来自客户端{}的数据，其topic为{} offset {} ", topicKey.clientID, topicKey.topicName, topicKey.offset);
            //resetClient(topicKey.clientID);
            if (!aliveTopicKeySet.contains(topicKey)) {
                topicKeysToStart.add(topicKey);
            } else {
                MessageReceiver receiver = topicKey2MessageReceiver.get(topicKey);
                receiver.addTopic(topicKey);
                topicLogger.info("{} add client {} on topic {} offset {}", receiver.toString(), topicKey.clientID, topicKey.topicName, topicKey.offset);
            }
            Snapshot.getDeviceBootTimeFromSnapshot(topicInfo.getClientId());
        }

        aliveTopicKeySet.addAll(topicKeysToStart);

        boolean foundFreeConsumer = false;


        if (!topicKeysToStart.isEmpty()) {
            for (MessageReceiver receiver : messageReceivers) {
                int availableTopicCount = MAX_Client_Per_Proessor - receiver.getTopicCount() - receiver.getTempTopicCount();
                if (availableTopicCount <= 0) {
                    continue;
                }

                if (topicKeysToStart.isEmpty()) {
                    break;
                }

                int addCount = Math.min(availableTopicCount, topicKeysToStart.size());

                for (int i = 0; i < addCount; i++) {
                    if (topicKeysToStart.isEmpty()) {
                        break;
                    }

                    TopicKey topicKey = topicKeysToStart.remove(0);

                    topicKey2MessageReceiver.put(topicKey, receiver);
                    receiver.addTopic(topicKey);
                    topicLogger.info("{} add client {} on topic {} offset {}", receiver.toString(), topicKey.clientID, topicKey.topicName, topicKey.offset);
                }
            }
        }

        /**
         *
         // find a consumer with has free space
         for (MessageReceiver receiver : messageReceivers) {
         if (receiver.getTopicCount() + receiver.getTempTopicCount() + topicKeysToStart.size() <= MAX_Client_Per_Proessor) {
         foundFreeConsumer = true;
         for (TopicKey topicKey : topicKeysToStart) {
         topicKey2MessageReceiver.put(topicKey, receiver);
         receiver.addTopic(topicKey);
         topicLogger.info("{} add client {} on topic {} offset {}", receiver.toString(), topicKey.clientID, topicKey.topicName, topicKey.offset);
         if (!CompilationConfig.DEBUG) {
         communicator.sendMessage(String.format("{action:add, clientID:%s}", topicKey.clientID));
         }
         }
         break;
         }
         }
         */

        // if cannot find, create a new consumer
        if (!topicKeysToStart.isEmpty()) {
            int newReceiverCount = (int) Math.ceil((double) topicKeysToStart.size() / (double) MAX_Client_Per_Proessor);
            for (int m = 0; m < newReceiverCount; m++) {
                if (topicKeysToStart.isEmpty()) {
                    break;
                }

                Consumer<Long, byte[]> consumer = new KafkaConsumer<>(props);

                // bridge between messageReceiver and messageProcessor
                LinkedBlockingQueue<ReceivedMessage> protobufParseMessageQueue = new LinkedBlockingQueue<>();

                MessageReceiver messageReceiver = new MessageReceiver(consumer, protobufParseMessageQueue, this);
                //MessageProcessor messageProcessor = new MessageProcessor(protobufParseMessageQueue);
                pool.execute(messageReceiver);
                //pool.execute(messageProcessor);
                int addCount = Math.min(MAX_Client_Per_Proessor, topicKeysToStart.size());
                for (int i = 0; i < addCount; i++) {
                    if (topicKeysToStart.isEmpty()) {
                        break;
                    }

                    TopicKey topicKey = topicKeysToStart.remove(0);

                    topicKey2MessageReceiver.put(topicKey, messageReceiver);
                    messageReceiver.addTopic(topicKey);
                    topicLogger.info("{} add client {} on topic {} offset {}", messageReceiver.toString(), topicKey.clientID, topicKey.topicName, topicKey.offset);

                }
                messageReceivers.add(messageReceiver);
            }
        }
    }

    public void requestStopTopic(Map<String, String> topicAndClientID) {
        Map<MessageReceiver, Set<TopicKey>> receiver2TopicKeys = new HashMap<>();
        for (Map.Entry<String, String> entry : topicAndClientID.entrySet()) {
            String topicName = entry.getKey();
            String clientId = entry.getValue();
            TopicKey topicKey = new TopicKey(topicName, clientId, "", "");
            friendlyLogger.info("请求停止处理来自客户端{}的数据，其topic为{}", clientId, topicName);
            logger.info("request client {} on topic {} to stop", clientId, topicName);
            topicLogger.info("request client {} on topic {} to stop", clientId, topicName);
            if (topicKey2MessageReceiver.containsKey(topicKey)) {
                MessageReceiver receiver = topicKey2MessageReceiver.get(topicKey);
                Set<TopicKey> topicNamesToStop = receiver2TopicKeys.getOrDefault(receiver, new HashSet<>());
                topicNamesToStop.add(topicKey);
                receiver2TopicKeys.put(receiver, topicNamesToStop);
            }
        }
        for (Map.Entry<MessageReceiver, Set<TopicKey>> entry : receiver2TopicKeys.entrySet()) {
            MessageReceiver receiver = entry.getKey();
            Set<TopicKey> topicNamesToStop = entry.getValue();
            receiver.requestStopTopic(topicNamesToStop);
        }
    }

    void reportSuccessStop(TopicKey topicKey) {
        aliveTopicKeySet.remove(topicKey);
        topicKey2MessageReceiver.remove(topicKey);
    }
}
