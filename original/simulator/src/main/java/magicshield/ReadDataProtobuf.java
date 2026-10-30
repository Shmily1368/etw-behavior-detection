package magicshield;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.google.gson.Gson;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;

/**
 * 从缓存文件读取处理好的待发送数据，发送到kafka
 */
public class ReadDataProtobuf {

    static ExecutorService pool = Executors.newFixedThreadPool(1);
    //static ScheduledExecutorService pool = Executors.newScheduledThreadPool(10);
    static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    static Gson gson = new Gson();

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, InterruptedException {

        if (args.length < 5) {
            System.err.println("please type params");
            return;
        }

        boolean randomStart = false;
        if (args.length > 0) {
            randomStart = Boolean.valueOf(args[0]);
        }

        String kafkaBootStrapServer = args[1];
        String speed = "normal";
        speed = args[2];

        // 一个线程调度
        // 定时任务线程池 发送

        int clientCount = Integer.valueOf(args[3]);
        int producerCount = Integer.valueOf(args[4]);
        pool = Executors.newFixedThreadPool(producerCount);
        String detectorId = "detector01";

        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootStrapServer);
        //props.put("acks", "all");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.ByteArraySerializer");
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 10 * 1024L * 1024L);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 100);
        props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 100000);
        props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);
        /*props.put("group.id","marple2");*/
        props.put("security.protocol", "SASL_PLAINTEXT");
        props.put("sasl.mechanism", "PLAIN");
        props.put("sasl.jaas.config","");


        List<Integer> startupTimes = Arrays.asList(192, 208, 242, 263, 107, 96, 262, 148, 193, 203, 21, 35, 228, 246, 127, 272, 145, 165, 226, 134, 233, 47, 167, 237, 210, 197, 298, 134, 175, 56, 158, 113, 150, 257, 237, 171, 228, 292, 297, 257, 272, 192, 47, 136, 52, 38, 299, 236, 223, 177, 174, 13, 16, 167, 288, 213, 173, 163, 134, 52, 42, 271, 35, 256, 250, 292, 287, 142, 46, 68, 289, 227, 5, 152, 154, 20, 63, 12, 59, 233, 33, 53, 123, 196, 87, 206, 107, 23, 49, 74, 115, 243, 50, 181, 26,
                232, 167, 25, 204, 218, 204, 209, 96, 218, 272, 31, 56, 87, 161, 60, 51, 125, 267, 257, 245, 28, 59, 215, 295, 56, 218, 294, 275, 96, 12, 259, 221, 208, 3, 165, 192, 78, 167, 215, 122, 270, 63, 241, 58, 230, 87, 281, 252, 246, 145, 221, 284, 19, 111, 266, 97, 71, 191, 191, 177, 90, 227, 84, 13, 96, 52, 166, 279, 51, 85, 10, 156, 19, 52, 158, 177, 92, 168, 176, 281, 1, 83, 189, 108, 176, 212, 265, 252, 226, 130, 86, 245, 65, 39, 46, 172, 3, 271, 166, 289, 15, 93, 117, 189, 92, 60,
                148, 229, 47, 215, 53, 191, 261, 219, 254, 77, 77, 173, 262, 95, 44, 184, 75, 41, 20, 43, 288, 224, 47, 152, 160, 3, 82, 192, 23, 245, 245, 137, 287, 2, 62, 225, 53, 238, 135, 260, 175, 155, 230, 298, 291, 274, 136, 112, 162, 19, 177, 116, 246, 207, 16, 208, 137, 243, 247, 287, 88, 205, 258, 108, 117, 151, 218, 58, 18, 38, 172, 257, 251, 26, 180, 197, 162, 235, 220, 67, 273, 117, 169, 105, 252, 289, 43, 201, 241, 123, 280, 168, 114, 116, 223, 57, 222, 105, 171);

        System.out.println(startupTimes.size());

        Properties controlProps = new Properties();
        controlProps.put("bootstrap.servers", kafkaBootStrapServer);
        //props.put("acks", "all");
        controlProps.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 100 * 1024);
        controlProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        controlProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");

        //System.setProperty("java.security.auth.login.config", "kafka_client_jaas.conf");
        controlProps.put("group.id","marple2");
        controlProps.put("security.protocol", "SASL_PLAINTEXT");
        controlProps.put("sasl.mechanism", "PLAIN");
        controlProps.put("sasl.jaas.config","");


        Producer<String, String> controlProducer = new KafkaProducer<>(controlProps);
        List<Producer<String, byte[]>> producers = new ArrayList<>(producerCount);
        for (int i = 0; i < producerCount; i++) {
            Producer<String, byte[]> producer = new KafkaProducer<>(props);
            producers.add(producer);
        }

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("datablockWithProto"));
        Object obj = ois.readObject();
        ois.close();

        List<DataBlock> list = (ArrayList<DataBlock>) obj;
        System.out.println("dataBlock Size:" + list.size());

        HashMap<String, Producer<String, byte[]>> clientId2Producer = new HashMap<>();
        HashMap<String, Integer> fakeCollectors = new HashMap<>();

        // 100 个client 300秒内启动完成
        for (int i = 1; i <= clientCount; i++) {
            Integer delay = 0;
            if (randomStart) {
                delay = startupTimes.get(i % startupTimes.size());
            }
            String clientId = "client_" + String.valueOf(i);
            System.out.println(clientId + " " + "delay " + delay);
            clientId2Producer.put(clientId, producers.get(i % producerCount));
            fakeCollectors.put(clientId, delay);

            ProducerRecord<String, String> clientInitRecord = new ProducerRecord<>("control",getClientInitMessage(clientId, detectorId));
            ProducerRecord<String, String> clientStartRecord = new ProducerRecord<>("control",getClientStartMessage(clientId, detectorId));

            // 发送client init
            controlProducer.send(clientInitRecord, (metadata, e) -> {
                System.out.println("client init send success. " + metadata.topic() + " " + clientInitRecord.value());
            });

            // 发送client start
            controlProducer.send(clientStartRecord, (metadata, e) -> {
                System.out.println("client start send success. " + metadata.topic() + " " + clientStartRecord.value());
            });
        }
        controlProducer.flush();
        controlProducer.close();

        long lastSendTime = 0;
        int i = 0;
        for (DataBlock dataBlock : list) {

            if (speed.equals("normal")) {
                Thread.sleep((dataBlock.sendTime - lastSendTime) * 1000);
            } else if (speed.equals("quick")) {

            } else {
                Thread.sleep(Long.valueOf(speed));
            }

            System.out.println(currentTime() + " " + ++i + "/" + list.size() + " " + dataBlock);
            for (Map.Entry<String, Integer> entry : fakeCollectors.entrySet()) {
                String clientId = entry.getKey();
                Integer delay = entry.getValue();
                Producer<String, byte[]> producer = clientId2Producer.get(clientId);
                //pool.schedule(new Job(clientId, dataBlock, producer), delay, TimeUnit.SECONDS);
                pool.execute(new Job(clientId, dataBlock, i, producer));
            }

            lastSendTime = dataBlock.sendTime;
        }

    }

    public static String currentTime() {
        return format.format(new Date());
    }

    public static String getClientInitMessage(String clientId, String detectorId) {
        Map<String, Object> map = new HashMap<>();
        map.put("CMD", "Client_Init");
        map.put("ClientID", clientId);
        map.put("TimeStamp", currentTime());
        map.put("DetectorID", detectorId);
        map.put("KafkaTopic", clientId);
        map.put("OsType", 0);
        map.put("ClientPlatform", "win10");
        map.put("uuid","15f5b133ce4e0fb36875bbd88f9591e6");
        String json = gson.toJson(map);
        return json;
    }

    public static String getClientStartMessage(String clientId, String detectorId) {
        Map<String, Object> map = new HashMap<>();
        map.put("CMD", "Client_Start");
        map.put("ClientID", clientId);
        map.put("TimeStamp", currentTime());
        map.put("DetectorID", detectorId);
        map.put("Offset", -1);
        map.put("Honeypot", 0);
        map.put("ip","127.0.0.1");
        map.put("uuid","15f5b133ce4e0fb36875bbd88f9591e6");
        String json = gson.toJson(map);
        return json;
    }

}