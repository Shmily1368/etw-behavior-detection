package magicshield;

import java.io.UnsupportedEncodingException;
import java.util.Properties;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

/**
 * KafkaTest
 */
public class KafkaTest {

    public static void main(String[] args) throws InterruptedException, UnsupportedEncodingException {
        Properties props = new Properties();
        props.put("bootstrap.servers", "127.0.0.1:9092");
        //props.put("acks", "all");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.ByteArraySerializer");

        byte[] message = "hello".getBytes("UTF8");

        Producer<String, byte[]> producer = new KafkaProducer<>(props);
        ProducerRecord<String, byte[]> producerRecord = new ProducerRecord<>("shifeng", message);

        producer.send(producerRecord, (metaData, e) -> {
            System.out.println("kafka send success. offset " + metaData.offset());
            if (e != null) {
                e.printStackTrace();
            }
        });

        int i = 0;
        while (true) {
            Thread.sleep(1000);
            System.out.println(i++);
        }
    }
}