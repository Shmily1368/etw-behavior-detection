package magicshield;

import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

/**
 * Job
 */
public class Job implements Runnable {
    private final Producer<String, byte[]> producer;
    private final DataBlock dataBlock;
    private final String clientId;
    private final Integer index;

    public Job(String clientId, DataBlock dataBlock, Integer index, Producer<String, byte[]> producer) {
        this.clientId = new String(clientId);
        this.dataBlock = new DataBlock(dataBlock);
        this.producer = producer;
        this.index = index;
    }

    @Override
    public void run() {
        long tid = Thread.currentThread().getId();
        ProducerRecord<String, byte[]> producerRecord = new ProducerRecord<>(clientId, this.dataBlock.data);
        System.out.println(ReadData.currentTime() + " " + clientId + " " + index + " run on thread " + tid + " :" + dataBlock);
        producer.send(producerRecord, (metaData, e) -> {
            if (e != null) {
                e.printStackTrace();
            }
            if (metaData.hasOffset()) {
                System.out.println(clientId + " " + index + " send success to kafka. tid=" + Thread.currentThread().getId() + " offset:" + metaData.offset() + " :" + dataBlock);
            }

        });
    }

}