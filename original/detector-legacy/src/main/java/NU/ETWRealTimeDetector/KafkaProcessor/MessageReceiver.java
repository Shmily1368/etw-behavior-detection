/*
package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.ETWproto.Etwdata.EventRecords;
import NU.ETWRealTimeDetector.EventRecord.ProtobufParsedMessage;
import NU.ETWRealTimeDetector.SysConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecords;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xerial.snappy.Snappy;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

class MessageReceiver implements Runnable {
    private Consumer<Long, byte[]> consumer;
    private LinkedBlockingQueue<ProtobufParsedMessage> downstream;
    private ConcurrentLinkedQueue<TopicKey> myTopicEntities;
    private Map<String, TopicKey> topicName2topicEntity;
    private Set<TopicKey> globalAliveTopicEntities;

    private final int maxFailTime = SysConfig.getInteger("MaxFailTime", 300);

    private final Logger logger = LoggerFactory.getLogger(MessageReceiver.class);

    public MessageReceiver(Consumer<Long, byte[]> consumer, LinkedBlockingQueue<ProtobufParsedMessage> downstream,
                           ConcurrentLinkedQueue<TopicKey> topicEntities,
                           Set<TopicKey> aliveTopicEntities
                          ){
        this.consumer = consumer;
        this.downstream = downstream;
        this.myTopicEntities = topicEntities;
        this.globalAliveTopicEntities = aliveTopicEntities;
        this.topicName2topicEntity = topicEntities.stream().collect(Collectors.toMap(
                e -> e.topicName,
                e -> e
        ));
    }

    @Override
    public void run() {
        boolean seek0 = SysConfig.getBoolean("Seek0", false);
        synchronized (consumer) {
            consumer.poll(0);
            if (seek0) {
                for (TopicKey topicEntity : myTopicEntities) {
                    TopicPartition topicPartition = new TopicPartition(topicEntity.topicName, 0);
                    consumer.seek(topicPartition, 0);
                }
            }
        }
        while (true) {
            for (TopicKey topicEntity : myTopicEntities) {
                if (!topicEntity.shouldStop) {
                    topicEntity.failTime = 0;
                }
                if (topicEntity.failTime >= maxFailTime) {
                    globalAliveTopicEntities.remove(topicEntity);
                    myTopicEntities.remove(topicEntity);
                    logger.info("stop topic {}", topicEntity.topicName);
                }
                topicEntity.failTime++;
            }

            ConsumerRecords<Long, byte[]> consumerRecords;
            synchronized (consumer) {
                consumerRecords = consumer.poll(1000);
                consumer.commitAsync();
            }

            if (consumerRecords.count() == 0) {
                logger.info("nothing");
                continue;
            }

            logger.info("something");
            consumerRecords.forEach(record -> {
                try {
                    byte[] uncompressedMessage = Snappy.uncompress(record.value());
                    String fromTopic = record.topic();

                    if (!topicName2topicEntity.containsKey(fromTopic)) {
                        this.topicName2topicEntity = myTopicEntities.stream().collect(Collectors.toMap(
                                e -> e.topicName,
                                e -> e
                        ));
                    }
                    TopicKey topicEntity = topicName2topicEntity.get(fromTopic);
                    topicEntity.failTime = 0;

                    EventRecords eventRecords = EventRecords.parseFrom(uncompressedMessage);
                    ProtobufParsedMessage message = new ProtobufParsedMessage(topicEntity.clientID, eventRecords);
                    downstream.put(message);
                } catch(Exception e) {
                    logger.error("uncompress error", e);
                }
            });
        }
    }
}
*/
package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.EventRecord.ReceivedMessage;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.SysConfig;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class MessageReceiver extends Thread {
    private static final int moduleSwitch = SysConfig.getInteger("Switch", 10);
    private static final int MAX_FAIL_TIME = SysConfig.getInteger("MaxFailTime", 300);
    private static final int Processor_Buffer_Size = SysConfig.getInteger("ProcessorBufferSize", 10);
    private static final Logger logger = LoggerFactory.getLogger("receiver");
    private static final Logger offsetLogger = LoggerFactory.getLogger("offset");
    private static final Logger friendlyLogger = LoggerFactory.getLogger("FriendlyLogger");
    private final Logger topicLogger = LoggerFactory.getLogger("topic");

    private ReceiverManager receiverManager;
    private Consumer<Long, byte[]> consumer;
    private LinkedBlockingQueue<ReceivedMessage> downstream;
    private ConcurrentMap<String, TopicKey> topicName2topicKey = new ConcurrentHashMap<>();
    private static ConcurrentMap<String, AtomicLong> client2TotalEvent = new ConcurrentHashMap<>();
    private static ConcurrentMap<String, AtomicLong> client2TotalPacket = new ConcurrentHashMap<>();
    private Collection<TopicPartition> _partitions = new ArrayList<>();
    private ConcurrentLinkedQueue<TopicKey> subscribedTopics = new ConcurrentLinkedQueue<>();

    private Neo4jClient neo4jClient = Neo4jClient.getInstance();
    private MessageProcessor processor = new MessageProcessor(null);

    private int id;
    private static boolean run = true;


    private static AtomicInteger counter = new AtomicInteger();

    private AtomicInteger tempCounter = new AtomicInteger();

    public MessageReceiver(Consumer<Long, byte[]> consumer, LinkedBlockingQueue<ReceivedMessage> downstream,
                           ReceiverManager receiverManager) {
        this.id = counter.incrementAndGet();
        this.consumer = consumer;
        this.downstream = downstream;
        this.receiverManager = receiverManager;
    }

    @Override
    public String toString() {
        return "MessageReceiver{" +
                "id=" + id +
                ", topicCount=" + topicName2topicKey.size() +
                ", tempTopicCount=" + tempCounter.intValue() +
                '}';
    }

    public static void shutdown() {
        run = false;
        System.out.println("shutdown");
    }

    void addTopic(TopicKey topicKey) {
        subscribedTopics.add(topicKey);
        tempCounter.incrementAndGet();
    }

    void addTopic(Collection<TopicKey> topicKeysToStart) {
        Iterator<TopicKey> iterator = topicKeysToStart.iterator();
        synchronized (consumer) {
            while (iterator.hasNext()) {
                TopicKey topicKey = iterator.next();
                String topicName = topicKey.getTopicName();
                topicLogger.info("{} adding to Subscription offset {}", topicName, topicKey.offset);
                if (topicName2topicKey.containsKey(topicName)) {
                    topicName2topicKey.get(topicName).setShouldStop(false);
                    topicName2topicKey.get(topicName).updateOffset(topicKey.offset);
                    topicLogger.info("{} already exist will seek offset to {}", topicName, topicKey.offset);
                    topicLogger.info("{} ", topicName2topicKey.get(topicName));
                    // remove already exist topic
                    //iterator.remove();
                } else {
                    topicName2topicKey.put(topicName, topicKey);
                }
            }
            // all already exist topic removed, now only new topics are left.
            if (topicKeysToStart.size() != 0) {
                updateSubscribedTopics();
            }
        }
    }

    void requestStopTopic(Collection<TopicKey> topicKeysToStop) {
        for (TopicKey topicKey : topicKeysToStop) {
            String topicName = topicKey.getTopicName();
            if (topicName2topicKey.containsKey(topicName)) {
                topicName2topicKey.get(topicName).setShouldStop(true);
            }
        }
    }

    private void stopAndReport(TopicKey topicKey) {
        logger.info("stop topic {}, clientId: {}", topicKey.getTopicName(), topicKey.getClientID());
        synchronized (consumer) {
            topicName2topicKey.remove(topicKey.getTopicName());
            updateSubscribedTopics();
        }
        receiverManager.reportSuccessStop(topicKey);
        // if no topic left, suspend
        if (getTopicCount() == 0) {
            logger.info("Receiver got no topic left, suspend");
        }
    }

    int getTopicCount() {
        return topicName2topicKey.size();
    }

    int getTempTopicCount() {
        return tempCounter.intValue();
    }

    private void updateSubscribedTopics() {
        topicLogger.info("updateSubscribedTopics");
        consumer.subscribe(topicName2topicKey.keySet(), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                topicLogger.info("onPartitionsRevoked");
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                topicLogger.info("onPartitionsAssigned");
                logger.info("Assigned {}", partitions);
                logger.info("topicName {}", topicName2topicKey.keySet().toString());
                _partitions = partitions;
                try {
                    Map<TopicPartition, Long> topicsEndOffset = consumer.endOffsets(partitions);
                    for (TopicPartition tp : partitions) {
                        String topic = tp.topic();
                        Long endOffset = topicsEndOffset.get(tp);

                        OffsetAndMetadata oam = consumer.committed(tp);

                        Optional<TopicKey> topicKey = topicName2topicKey.values().stream().filter(t -> t.topicName.equals(tp.topic())).findFirst();
                        if (topicKey.isPresent() && topicKey.get().shouldSeekToOffset) {
                            long committedOffset = 0;
                            if (oam != null) {
                                committedOffset = oam.offset();
                                topicLogger.info("{} EndOffset is {} Current offset is {}", topic, endOffset, oam.offset());
                            } else {
                                topicLogger.info("{} EndOffset is {} No committed offsets", topic, endOffset);
                            }

                            // 更新到指定的offset
                            Integer offset = topicKey.get().offset;
                            if (offset <= endOffset && offset > committedOffset) {
                                topicLogger.info("{} Seeking to {}", topic, offset);
                                consumer.seek(tp, offset);
                            } else {
                                topicLogger.info("{} not seeking to {} EndOffset is {} committed offset is {}", topic, offset, endOffset, committedOffset);
                            }
                            topicKey.get().hasBeenSeekToOffset();
                        }
                    }

                } catch (Exception e) {
                    logger.error(String.format("onPartitionsAssigned error %s", partitions), e);
                }
            }
        });

        //  当执行订阅时，判断已经订阅的topic 是否要更新offset
        Set<TopicPartition> topicPartitions = consumer.assignment();
        topicLogger.info("assignment {} ", topicPartitions);
        topicLogger.info("shouldSeekTopicKey {}", topicName2topicKey.values().stream().filter(t -> t.shouldSeekToOffset).collect(Collectors.toList()));
        Map<TopicPartition, Long> topicsEndOffset = consumer.endOffsets(topicPartitions);
        if (!topicsEndOffset.isEmpty()) {
            topicsEndOffset.forEach((tp, endOffset) -> {
                String topic = tp.topic();
                Optional<TopicKey> topicKey = topicName2topicKey.values().stream().filter(t -> t.topicName.equals(topic)).findFirst();
                if (topicKey.isPresent() && topicKey.get().shouldSeekToOffset) {
                    // 更新到指定的offset
                    Integer offset = topicKey.get().offset;
                    topicLogger.info("{} should seek to {}", topic, offset);

                    long committedOffset = 0;
                    OffsetAndMetadata oam = consumer.committed(tp);
                    if (oam != null) {
                        committedOffset = oam.offset();
                        topicLogger.info("{} EndOffset is {} Current offset is {}", topic, endOffset, oam.offset());
                    } else {
                        topicLogger.info("{} EndOffset is {} No committed offsets", topic, endOffset);
                    }

                    boolean seeked = false;
                    if (offset > endOffset) {
                        topicLogger.info("{} offset {} greater than endOffset {} will seek to end");
                        consumer.seekToEnd(Collections.singleton(tp));
                        seeked = true;
                    }

                    if (offset <= endOffset && offset > committedOffset) {
                        topicLogger.info("{} Seeking to {}", topic, offset);
                        consumer.seek(tp, offset);
                        seeked = true;
                    }

                    if (!seeked) {
                        topicLogger.info("{} not Seeking to {}", topic, offset);
                    }
                    topicKey.get().hasBeenSeekToOffset();
                }
            });
        }
    }

    @Override
    public void run() {
        int pollCount = 0;
        try {

            while (run) {
                if (!subscribedTopics.isEmpty()) {
                    List<TopicKey> topicKeys = new ArrayList<>();
                    while (true) {
                        TopicKey topicKey = subscribedTopics.poll();
                        if (topicKey == null) {
                            break;
                        }
                        topicKeys.add(topicKey);
                        tempCounter.decrementAndGet();
                    }
                    addTopic(topicKeys);
                }

                int neo4jClientQueueSize = neo4jClient.queueSize.intValue();
                if (neo4jClientQueueSize > 500000) {
                    logger.error("waiting for 1s. neo4jClient queue size:" + neo4jClientQueueSize);
                    try {
                        Thread.sleep(1000);
                        continue;
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                if (downstream.size() > Processor_Buffer_Size) {
                    logger.info("waiting for 20ms. downstream size:" + downstream.size());
                    try {
                        Thread.sleep(20);
                        continue;
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                if (pollCount % 100 == 0) {
                    for (Map.Entry<String, TopicKey> entry : topicName2topicKey.entrySet()) {
                        TopicKey topicKey = entry.getValue();
                        if (!topicKey.getShouldStop()) {
                            topicKey.setFailTime(0);
                        }
                        if (topicKey.getFailTime() >= MAX_FAIL_TIME) {
                            stopAndReport(topicKey);
                        } else {
                            topicKey.setFailTime(topicKey.getFailTime() + 1);
                        }
                    }
                }

                ConsumerRecords<Long, byte[]> consumerRecords = null;
                synchronized (consumer) {
                    if (getTopicCount() != 0) {
                        consumerRecords = consumer.poll(Duration.ofMillis(1000));
                    }
                    pollCount++;
                }


                if (consumerRecords == null) {
                    try {
                        Thread.sleep(1000);
                    } catch (Exception e) {
                        logger.error("interrupted", e);
                    }
                    continue;
                }
                if (consumerRecords.count() == 0) {
                    logger.info("nothing");
                    continue;
                }


//            if (paused && downstream.size() <= 80) {
//                paused = false;
//                consumer.resume(_partitions);
//                logger.info("downstream size is {} resume", downstream.size());
//            }
//
//            if (consumerRecords == null || consumerRecords.count() == 0) {
//                if (pollCount % 50 == 0) {
//                    logger.info("nothing {} downstream size {}", pollCount, downstream.size());
//                }
//                continue;
//            }

//            if (!paused && downstream.size() > 100) {
//                paused = true;
//                consumer.pause(_partitions);
//                logger.info("downstream size is {} Suspend fetching", downstream.size());
//            }

                consumerRecords.forEach(record -> {
                    try {
                    /*

                    byte[] uncompressedMessage = Snappy.uncompress(record.value());
                    String fromTopic = record.topic();
                    long offset = record.offset();
                    logger.info("something on topic {}, offset {}", fromTopic, offset);
                    friendlyLogger.info("读取到topic {} 上的数据, offset为{}", fromTopic, offset);

                    TopicKey topicKey = topicName2topicKey.get(fromTopic);
                    topicKey.setFailTime(0);

                    EventRecords eventRecords = EventRecords.parseFrom(uncompressedMessage);
                    AtomicLong count;
                    AtomicLong packet;
                    if (client2TotalEvent.containsKey(fromTopic)) {
                        count = client2TotalEvent.get(fromTopic);
                    } else {
                        count = new AtomicLong();
                    }

                    if (client2TotalEvent.containsKey(fromTopic)) {
                        packet = client2TotalPacket.get(fromTopic);
                    } else {
                        packet = new AtomicLong();
                    }

                    count.addAndGet(eventRecords.getProcessIDCount());
                    packet.incrementAndGet();

                    client2TotalEvent.put(fromTopic, count);
                    client2TotalPacket.put(fromTopic, packet);
                    outputEventCount(fromTopic, count, packet);

                    ProtobufParsedMessage message = new ProtobufParsedMessage(topicKey.getClientID(), eventRecords);
                    downstream.put(message);
                     */

                        String fromTopic = record.topic();
                        TopicKey topicKey = topicName2topicKey.get(fromTopic);
                        topicKey.setFailTime(0);
                        ReceivedMessage receivedMessage = new ReceivedMessage(record.value(), topicKey.clientID, topicKey.uuid, topicKey.ip);
                        if (moduleSwitch <= 1) {
                            return;
                        }

                        offsetLogger.info("{} {}", fromTopic, record.offset());

                        processor.process(receivedMessage);
                        //downstream.put(receivedMessage);
                    } catch (Exception e) {
                        logger.error("uncompress error", e);
                    }
                });
            }
        } catch (Exception e) {
            logger.error("kafka consumer error", e);
        } finally {
            consumer.close();
        }
    }

}
