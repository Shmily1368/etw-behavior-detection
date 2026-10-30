package NU.ETWRealTimeDetector.Neo4j;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.FileNodeNew;
import NU.ETWRealTimeDetector.Framework.Node.FileNodeV2;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Neo4j.Message.*;
import NU.ETWRealTimeDetector.Neo4j.Task.*;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.acl.AclOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class Neo4jClient extends Thread {
    private static final int moduleSwitch = SysConfig.getInteger("Switch", 10);
    private static final Logger logger = LoggerFactory.getLogger(Neo4jClient.class);
    private static final Logger taskLogger = LoggerFactory.getLogger("taskCounter");
    private static final String kafkaBootStrapServer = SysConfig.getString("KafkaBrokerServer");
    private static final String ack = SysConfig.getString("ack", "0");
    private static final String retries = SysConfig.getString("retries", "3");
    private static final int max_in_flight_requests_per_connection = SysConfig.getInteger("MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION", 1);
    private static final String kafkaTopic = SysConfig.getString("IllustratorTopic", "illustrator_dev");
    private static boolean sasl = SysConfig.getBoolean("SASL", false);

    public static final AtomicInteger sendCount = new AtomicInteger();

    private static Neo4jClient instance;

    private Producer<String, byte[]> producer;

    public static synchronized Neo4jClient getInstance() {
        if (instance == null) {
            instance = new Neo4jClient();
            instance.start();
        }
        return instance;
    }

    private Neo4jClient() {

        Output output = new Output(1024, -1);

        Kryo kryo = new Kryo();
        kryo.register(AddFileNodeMessage.class);
        kryo.register(RemoveFileNodeMessage.class);
        kryo.register(AddLabelMessage.class);
        kryo.register(AddNodeRelationMessage.class);
        kryo.register(AddProcessNodeMessage.class);
        kryo.register(AddPropertyMessage.class);
        kryo.register(ChangeNameMessage.class);
        kryo.register(DeleteNodeRelationMessage.class);
        kryo.register(DrawAttackGraphMessage.class);
        kryo.register(DrawProcessRelationMessage.class);
        kryo.register(DrawSensitiveProgramProcessRelationMessage.class);
        kryo.register(UpdateNameMessage.class);
        kryo.register(UpdateProcessNodeMessage.class);
        kryo.register(AddZoneIdentifierMessage.class);
        kryo.register(HashMap.class);

        BaseTask.setKryo(kryo);
        BaseTask.setOutput(output);
    }

    private ConcurrentLinkedQueue<BaseTask> queue = new ConcurrentLinkedQueue<>();
    private Set<BaseTask> set = ConcurrentHashMap.newKeySet();
    public AtomicInteger queueSize = new AtomicInteger(0);
    public AtomicInteger counter = new AtomicInteger(0);
    public AtomicInteger fileNodeCounter = new AtomicInteger(0);
    public AtomicInteger processNodeCounter = new AtomicInteger(0);
    public AtomicInteger processRelationCounter = new AtomicInteger(0);
    public AtomicInteger deleteNodeCounter = new AtomicInteger(0);
    public AtomicInteger addLabelCounter = new AtomicInteger(0);
    public AtomicInteger addPropertyCounter = new AtomicInteger(0);
    public AtomicInteger renameFileCounter = new AtomicInteger(0);
    public AtomicInteger updateFileCounter = new AtomicInteger(0);
    public AtomicInteger updateProcessNodeCounter = new AtomicInteger(0);

    private final int cacheSize = 10000;

    public void addFileNode(FileNodeNew node) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddFileNodeTask task = new AddFileNodeTask(node.getClientId(), node.getUuid(), node.getFilePath());

        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                fileNodeCounter.incrementAndGet();
            }
        }
    }

    public void addZoneIdentifier(String clientId, Long uuid, Integer zoneId, String referrerUrl, String hostUrl, String fileName) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddZoneIdentifierTask task = new AddZoneIdentifierTask(clientId, uuid, zoneId, referrerUrl, hostUrl, fileName);

        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
        }
    }

    public void addFileNodeV2(FileNodeV2 node) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddFileNodeTask task = new AddFileNodeTask(node.getClientId(), node.getUuid(), node.getFilePath());

        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                fileNodeCounter.incrementAndGet();
            }
        }
    }

    public void removeTempFile(String clientId, Long uuid) {
        if (moduleSwitch <= 4) {
            return;
        }
        RemoveFileNodeTask task = new RemoveFileNodeTask(clientId, uuid);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
        }
    }

    public void addProcessNode(Process process) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddProcessNodeTask task = new AddProcessNodeTask(process);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                processNodeCounter.incrementAndGet();
            }
        }
    }

    public void addProcessRelation(String clientId, Node fromNode, Node toNode, EventType eventType, long timestamp) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddNodeRelationTask task = new AddNodeRelationTask(clientId, fromNode, toNode, eventType, timestamp);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                processRelationCounter.incrementAndGet();
            }
        }
    }

    public void deleteNodeRelation(String clientId, Node fromNode, Node toNode, EventType eventType) {
        DeleteNodeRelationTask task = new DeleteNodeRelationTask(clientId, fromNode, toNode, eventType);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                deleteNodeCounter.incrementAndGet();
            }
        }
    }

    public void addLabel(String clientId, Node fromNode, Node toNode, LabelType fromLabel, LabelType toLabel, EventType eventType, long timestamp) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddLabelTask task = new AddLabelTask(clientId, fromNode, toNode, fromLabel, toLabel, eventType, timestamp);

        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                addLabelCounter.incrementAndGet();
            }
        }
    }

    public void addLabel(String clientId, Node fromNode, Node toNode, LabelType fromLabel, LabelType toLabel, EventType eventType, long timestamp, HashMap<String, String> extend) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddLabelTask task = new AddLabelTask(clientId, fromNode, toNode, fromLabel, toLabel, eventType, timestamp, extend);

        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                addLabelCounter.incrementAndGet();
            }
        }
    }

    public void addProperty(Node node, String key, String value) {
        if (moduleSwitch <= 4) {
            return;
        }
        AddPropertyTask task = new AddPropertyTask(node, key, value);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                addPropertyCounter.incrementAndGet();
            }
        }
    }

    public void renameFile(String clientId, long oldFileNodeUuid, long newFileNodeUuid, String newFileName) {
        if (moduleSwitch <= 4) {
            return;
        }
        ChangeNameTask task = new ChangeNameTask(clientId, oldFileNodeUuid, newFileNodeUuid, newFileName);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                renameFileCounter.incrementAndGet();
            }
        }
    }

    public void updateFileName(String clientId, long uuid, String newFileName) {
        if (moduleSwitch <= 4) {
            return;
        }
        UpdateNameTask task = new UpdateNameTask(clientId, uuid, newFileName);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                updateFileCounter.incrementAndGet();
            }
        }
    }

    public void updateProcessNode(String clientId, long uuid, String propertyName, Object propertyValue) {
        if (moduleSwitch <= 4) {
            return;
        }
        UpdateProcessNodeTask task = new UpdateProcessNodeTask(clientId, uuid, propertyName, propertyValue);
        if (!set.contains(task)) {
            queue.add(task);
            queueSize.incrementAndGet();
            set.add(task);
            if (CompilationConfig.DEBUG) {
                counter.incrementAndGet();
                updateProcessNodeCounter.incrementAndGet();
            }
        }
    }

    public void drawSensitiveProgramProcessRelationGraph(String clientId, Process process, String cmds, HashMap<String, String> extend) {
        if (moduleSwitch <= 4) {
            return;
        }
        DrawSensitiveProgramProcessRelationTask task = new DrawSensitiveProgramProcessRelationTask(process, clientId, cmds, extend);
        queue.add(task);
        queueSize.incrementAndGet();

        if (CompilationConfig.DEBUG) {
            counter.incrementAndGet();
        }
    }

    public void drawProcessRelationGraph(String clientId, Process process, String eventId) {
        if (CompilationConfig.DEBUG) {
            return;
        }
        DrawProcessRelationTask task = new DrawProcessRelationTask(process, clientId, eventId);
        queue.add(task);
        queueSize.incrementAndGet();

        if (CompilationConfig.DEBUG) {
            counter.incrementAndGet();
        }
    }

    public void drawAttackGraph(String clientId, Process process, String eventId) {
        if (CompilationConfig.DEBUG) {
            return;
        }
        DrawAttackGraphTask task = new DrawAttackGraphTask(process, clientId, eventId);
        queue.add(task);
        queueSize.incrementAndGet();
        if (CompilationConfig.DEBUG) {
            counter.incrementAndGet();
        }
    }

    @Override
    public void run() {
        // 检查是否有topic授权
        //KafkaUtil.ensureAuthorization(kafkaTopic, "detector", AclOperation.WRITE);

        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootStrapServer);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.ByteArraySerializer");
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "gzip");
        props.put(ProducerConfig.ACKS_CONFIG, ack);
        //props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 1024 * 1024 * 1024L);
        //props.put(ProducerConfig.BATCH_SIZE_CONFIG, 100);
        //props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 10000);
        // 最大未确认的Request数量，该参数设置为1 代表 有序
        props.put(ProducerConfig.RETRIES_CONFIG, retries);
        props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, max_in_flight_requests_per_connection);
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, "60000");
        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        producer = new KafkaProducer<>(props);
        BaseTask.setProducer(producer);

        int flushCounter = 0;
        while (true) {
            if (queueSize.intValue() > 0 && queueSize.intValue() % 1000 == 0) {
                logger.info("neo4jClient queue size: {}", queueSize.intValue());
            }
            if (queueSize.intValue() > cacheSize) {
                logger.info("flush {}", queueSize.intValue());
                flush(cacheSize);
                flushCounter = 0;
            } else {
                if (queueSize.intValue() != 0) {
                    flushCounter++;
                }
                if (flushCounter > 6) {
                    logger.info("force flush {}", queueSize.intValue());
                    flush(queueSize.intValue());
                    flushCounter = 0;
                }
                try {
                    Thread.sleep(500L);
                } catch (InterruptedException e) {
                    logger.error("interrupted", e);
                }
            }
        }
    }

    private void flush(int flushSize) {
        try {
            for (int i = 0; i < flushSize; i++) {
                BaseTask task = queue.poll();
                queueSize.decrementAndGet();
                task.performTask();
                set.remove(task);
                sendCount.incrementAndGet();
                if (sendCount.get() % 10000 == 0) {
                    taskLogger.info("send: {}", sendCount.get());
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

}
