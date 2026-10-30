package NU.ETWRealTimeDetector.Neo4j.Task;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.Neo4j.MessageType;
import NU.ETWRealTimeDetector.SysConfig;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicInteger;

public abstract class BaseTask {

    private static final String kafkaTopic = SysConfig.getString("IllustratorTopic", "illustrator_dev");
    private static final Logger logger = LoggerFactory.getLogger("neo4jTask");
    private static final Logger taskLogger = LoggerFactory.getLogger("taskCounter");
    protected static Producer<String, byte[]> _producer;
    protected static Kryo _kryo;
    protected static Output _output;

    public static final AtomicInteger successCount = new AtomicInteger();

    String clientId;

    public static void setProducer(Producer<String, byte[]> producer) {
        _producer = producer;
    }

    public static void setKryo(Kryo kryo) {
        _kryo = kryo;
    }

    public static void setOutput(Output output) {
        _output = output;
    }

    public BaseTask(String clentId) {
        this.clientId = clentId;
    }

    public abstract void performTask();

    public void send(byte[] message, MessageType messageType) {
        if (CompilationConfig.DEBUG) {
            return;
        }
        ProducerRecord<String, byte[]> producerRecord = new ProducerRecord<>(kafkaTopic, message);
        producerRecord.headers().add(new RecordHeader("type", getIntBytes(messageType.ordinal())));
        _producer.send(producerRecord, (metaData, e) -> {
            if (e != null) {
                e.printStackTrace();
            }
            if (metaData.hasOffset()) {
                //logger.info(String.format("send success to kafka. offset %d %s", metaData.offset(), message));
                successCount.incrementAndGet();
                if (successCount.get() % 10000 == 0) {
                    taskLogger.info("success: {}", successCount.get());
                }
            }
        });
    }

    public static byte[] getIntBytes(int data) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(data);
        byte[] bytes = buffer.array();
        return bytes;
    }

    public static int byte2Int(byte[] bytes) {
        return (bytes[0] & 0xff) << 24 | (bytes[1] & 0xff) << 16 | (bytes[2] & 0xff) << 8 | (bytes[3] & 0xff);
    }
}