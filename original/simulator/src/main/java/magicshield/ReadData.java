package magicshield;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;

/**
 * ReadData
 */
public class ReadData {

    static ScheduledExecutorService pool = Executors.newScheduledThreadPool(1);
    static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @SuppressWarnings("unchecked")
    public static void main(String[] args)
            throws FileNotFoundException, IOException, ClassNotFoundException, InterruptedException {

        // 一个线程调度
        // 定时任务线程池 发送

        // producerCount= clientCount / 5 每个client5s需要发送一个数据，例如 300 client，平均同时会有60client，应该有60个producer
        // producerCount= 5 会有2个线程发送数据给kafka broker, 短时间内的消息会合并一起发送
        int producerCount = 1;
        int clientCount = 1;
        int startupTime = 10;

        Properties props = new Properties();
        props.put("bootstrap.servers", "127.0.0.1:9092");
        //props.put("acks", "all");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.ByteArraySerializer");

        List<Producer<String, byte[]>> producers = new ArrayList<>(producerCount);
        for (int i = 0; i < producerCount; i++) {
            Producer<String, byte[]> producer = new KafkaProducer<>(props);
            producers.add(producer);
        }

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("datablock"));
        Object obj = ois.readObject();
        ois.close();

        List<DataBlock> list = (ArrayList<DataBlock>) obj;

        HashMap<String, Producer<String, byte[]>> clientId2Producer = new HashMap<>();
        HashMap<String, Integer> fakeCollectors = new HashMap<>();

        // 100 个client 300秒内启动完成
        Random random = new Random();
        for (int i = 0; i < clientCount; i++) {
            Integer delay = random.nextInt(startupTime);
            String clientId = "fakeCollector" + i;
            System.out.println(clientId + " " + "delay " + delay);
            clientId2Producer.put(clientId, producers.get(i % producerCount));
            fakeCollectors.put(clientId, delay);
        }

        long lastSendTime = 0;
        int i = 0;
        for (DataBlock dataBlock : list) {
            i++;
            Thread.sleep((dataBlock.sendTime - lastSendTime) * 1000);
            System.out.println(currentTime() + " " + dataBlock);

            for (Map.Entry<String, Integer> entry : fakeCollectors.entrySet()) {
                String clientId = entry.getKey();
                Integer delay = entry.getValue();
                Producer<String, byte[]> producer = clientId2Producer.get(clientId);
                pool.schedule(new Job(clientId, dataBlock, i, producer), delay, TimeUnit.SECONDS);
            }

            lastSendTime = dataBlock.sendTime;
        }

    }

    public static String currentTime() {
        return format.format(new Date());
    }

}