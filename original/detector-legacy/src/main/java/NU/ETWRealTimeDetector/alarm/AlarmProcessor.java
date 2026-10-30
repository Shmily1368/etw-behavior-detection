package NU.ETWRealTimeDetector.alarm;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static java.util.Arrays.asList;

public class AlarmProcessor extends Thread {
    private static final String bootstrapServers = SysConfig.getString("KafkaBrokerServer");
    private static final String alarmConsumerGroup = SysConfig.getString("AlarmConsumerGroup");
    private static final String eventTopic = SysConfig.getString("EventTopic");
    private static final String alarmTopic = SysConfig.getString("AlarmTopic");
    private static final Logger logger = LoggerFactory.getLogger("alarm");
    private static boolean sasl = SysConfig.getBoolean("SASL", false);

    private KafkaConsumer<String, String> consumer;
    private KafkaProducer<String, String> producer;

    private boolean running = true;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static HashMap<String, String> eventType2Name = new HashMap<>();

    static {
        eventType2Name.put("IllegalFileOperation", "文档防篡改");
        eventType2Name.put("DownloadExecution", "恶意程序");
        eventType2Name.put("ExsitingMalware", "驻留病毒");
        eventType2Name.put("DetectedByUsers", "可疑木马");
        eventType2Name.put("ReflectiveLoadingAttack", "内存攻击");
        eventType2Name.put("ScriptBasedAttack", "脚本攻击");
        eventType2Name.put("Powershell", "Powershell检测");
        eventType2Name.put("Ransomeware", "勒索");
        eventType2Name.put("Mining", "恶意挖矿");
        eventType2Name.put("IllegalDeleteLog", "日志异常删除");
        eventType2Name.put("RegistryTamper", "注册表篡改");
        eventType2Name.put("SensitiveFile", "敏感文件操作");
        eventType2Name.put("RequestMaliciousDomain", "访问恶意域名");
        eventType2Name.put("IllegalConnectInternet", "非法连接互联网");
        eventType2Name.put("PortScan", "端口扫描超限");
        eventType2Name.put("HoneyPort", "敏感端口扫描");
        eventType2Name.put("IllegalProcess", "违规进程");
        eventType2Name.put("ReverseShell", "反弹shell");
        eventType2Name.put("PrivilegeEscalation", "非法提权");
        eventType2Name.put("Webshell", "中国菜刀命令执行");
        eventType2Name.put("Tunnel", "隧道搭建");
        eventType2Name.put("FakeSystemProcess", "伪造系统进程运行");
        eventType2Name.put("DangerousCommand", "可疑命令执行");
        eventType2Name.put("ServiceProcess", "对外服务进程异常执行");
        eventType2Name.put("MBR", "MBR防护");
        eventType2Name.put("IllegalLoginIp", "非法IP登录");
        eventType2Name.put("IllegalLoginAccount", "非法用户登录");
        eventType2Name.put("IllegalPrint", "非法打印");
        eventType2Name.put("IllegalCDROM", "非法刻录");
        eventType2Name.put("IllegalUSBStorage", "非法USB存储接入");
        eventType2Name.put("SystemOverload", "客户端满负荷运行");
    }

    public AlarmProcessor() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, alarmConsumerGroup);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 100);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 1000);

        if (sasl) {
            props.put("security.protocol", "SASL_PLAINTEXT");
            props.put("sasl.mechanism", "PLAIN");
            props.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        consumer = new KafkaConsumer<>(props);

        Properties producerProps = new Properties();
        producerProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        producerProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        producerProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        producerProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "gzip");
        producerProps.put(ProducerConfig.ACKS_CONFIG, "0");
        producerProps.put(ProducerConfig.RETRIES_CONFIG, "3");
        //props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);
        //props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, "60000");
        if (sasl) {
            producerProps.put("security.protocol", "SASL_PLAINTEXT");
            producerProps.put("sasl.mechanism", "PLAIN");
            producerProps.put("sasl.jaas.config", KafkaUtil.getCypher());
        }
        producer = new KafkaProducer<>(producerProps);
    }

    @Override
    public void run() {

        consumer.subscribe(asList(eventTopic), new ConsumerRebalanceListener() {
            @Override
            public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                logger.warn("onPartitionRevoked.");
            }

            @Override
            public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                logger.info("onPartitionAssigned.");
                logger.info("Assigned {}", partitions);
                try {
                    Map<TopicPartition, Long> topicsEndOffset = consumer.endOffsets(partitions);
                    for (TopicPartition tp : partitions) {
                        String topic = tp.topic();
                        Long endOffset = topicsEndOffset.get(tp);

                        OffsetAndMetadata oam = consumer.committed(tp);
                        long committedOffset = 0;
                        if (oam != null) {
                            committedOffset = oam.offset();
                            logger.info("{} EndOffset is {} Current offset is {}", topic, endOffset, oam.offset());
                        } else {
                            logger.info("{} EndOffset is {} No committed offsets", topic, endOffset);
                        }

                        // 更新到指定的topic
                        // consumer.seek(tp, 0);

                    }
                    //consumer.seekToBeginning(partitions);
                } catch (Exception e) {
                    logger.error("onPartitionAssigned error", e);
                }
            }
        });

        while (running) {
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
            if (records == null || records.isEmpty()) {
                continue;
            }

            records.forEach(record -> {
                try {
                    String event = record.value();
                    long offset = record.offset();

                    if (event.contains("DrawAttackGraph") || event.contains("DrawProcessRelation")) {
                        return;
                    }

                    sendMessage(event);
                    logger.info("offset:{} message:{}", offset, event);
                } catch (Exception e) {
                    logger.error("error", e);
                }

            });
        }
        consumer.close();
    }

    private void sendMessage(String event) {

        try {

            JSONObject object = JSONObject.parseObject(event);
            String eventType = object.getString("log_name");
            String eventId = object.getString("id");
            long timestamp = object.getLongValue("timestamp");
            int level = object.getInteger("level");
            String ip = object.getString("ip");
            String uuid = object.getString("uuid");
            String hostName = object.getString("host_name");
            if (StringUtils.isEmpty(hostName)) {
                hostName = object.getString("hostname");
            }

            String alarmTime = "";
            try {
                alarmTime = sdf.format(timestamp);
            } catch (IllegalArgumentException e) {
                logger.error("error", e);
            }
            if (ip == null) {
                ip = "";
            }

            String eventName = eventType2Name.get(eventType);

            JSONObject params = new JSONObject();
            params.put("alarm_type", "event");
            params.put("alarm_time", alarmTime);
            params.put("theme", eventType);
            params.put("level", level);
            params.put("event_id", eventId);
            params.put("host_ip", ip);
            params.put("host_name", hostName);
            params.put("event_name", eventName);
            params.put("uuid", uuid);

            String json = params.toString();
            ProducerRecord<String, String> record = new ProducerRecord<>(alarmTopic, json);
            producer.send(record, (metaData, e) -> {
                if (e != null) {
                    logger.error("send alarm to kafka error", e);
                }
                if (metaData.hasOffset()) {
                    logger.info("send success to {}. offset {} message {}", alarmTopic, metaData.offset());
                }
            });
        } catch (Exception e) {
            logger.error("error", e);
        }
    }
}
