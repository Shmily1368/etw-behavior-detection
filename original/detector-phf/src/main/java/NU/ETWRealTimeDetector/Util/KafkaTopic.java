package NU.ETWRealTimeDetector.Util;


import NU.ETWRealTimeDetector.SysConfig;
import org.apache.kafka.clients.admin.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;


public class KafkaTopic {

    private static AdminClient kafkaAdminClient;
    private static Logger logger = LoggerFactory.getLogger(KafkaTopic.class);
    private static boolean sasl = SysConfig.getBoolean("SASL", false);

    public KafkaTopic(String brokerUrl) {
        Properties properties = new Properties();
        properties.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, brokerUrl);

        if (sasl) {
            properties.put("security.protocol", "SASL_PLAINTEXT");
            properties.put("sasl.mechanism", "PLAIN");
            properties.put("sasl.jaas.config", KafkaUtil.getAdminCypher());
        }

        kafkaAdminClient = KafkaAdminClient.create(properties);
    }

    public void deleteTopic(boolean delete, String topicPrefix) throws ExecutionException, InterruptedException {
        System.out.println("DeleteTopic:" + delete + " topicPrefix:" + topicPrefix);
        if (!delete)
            return;
        if (topicPrefix == null || topicPrefix.length() == 0)
            return;

        if (kafkaAdminClient == null) {
            throw new NullPointerException();
        }

        try {
            List<String> deleteTopicList;

            ListTopicsResult topicList = kafkaAdminClient.listTopics(new ListTopicsOptions().timeoutMs(30000));
            deleteTopicList = topicList.names().get().stream().filter(name -> name.contains(topicPrefix)).collect(Collectors.toList());

            if (deleteTopicList.isEmpty())
                return;

            for (String topic : deleteTopicList) {
                try {
                    DeleteTopicsResult deleteTopicsResult = kafkaAdminClient.deleteTopics(asList(topic), new DeleteTopicsOptions().timeoutMs(10000));
                    deleteTopicsResult.all().get();
                } catch (Exception e) {
                    logger.warn(String.format("topic清空超时 %s %s ", topic, e.getMessage()));
                }
            }
            System.out.println("topic已清空 :" + String.join(",", deleteTopicList));
        } catch (Exception e) {
            logger.warn(String.format("topic清空失败 %s ", e.getMessage()));
        }
    }

    private static class CommonClientConfigs {
        private static String BOOTSTRAP_SERVERS_CONFIG = "bootstrap.servers";
    }
}
