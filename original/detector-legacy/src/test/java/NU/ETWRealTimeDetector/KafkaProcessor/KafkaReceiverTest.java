package NU.ETWRealTimeDetector.KafkaProcessor;

import org.junit.Test;

import java.util.concurrent.LinkedBlockingQueue;

public class KafkaReceiverTest {

    @Test
    public void run() throws InterruptedException {
        String bootstrapServers = "127.0.0.1:9092";
        String group = "marple2";
        LinkedBlockingQueue queue = new LinkedBlockingQueue<String>();
        KafkaReceiver kafkaReceiver = new KafkaReceiver(bootstrapServers, group, queue);
        kafkaReceiver.start();
        while (true){
            Thread.sleep(1000);
        }
    }
}