package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeAclsOptions;
import org.apache.kafka.clients.admin.DescribeAclsResult;
import org.apache.kafka.clients.admin.KafkaAdminClient;
import org.apache.kafka.common.acl.*;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePatternFilter;
import org.apache.kafka.common.resource.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.Properties;
import java.util.concurrent.ExecutionException;

public class KafkaUtil {
    private static final String kafkaBrokerServer = SysConfig.getString("KafkaBrokerServer", "");
    private static Logger logger = LoggerFactory.getLogger("authorization");
    private static final String jaasTemplate = "org.apache.kafka.common.security.scram.ScramLoginModule required username='kafka' password='';";
    private static final String adminJaasTemplate = "org.apache.kafka.common.security.scram.ScramLoginModule required username='kafka' password='';";
    private static AdminClient kafkaAdminClient;

    private static HashMap<String, Boolean> cache = new HashMap<>();

    public static String getCypher() {
        return jaasTemplate;
    }

    public static String getAdminCypher() {
        return adminJaasTemplate;
    }

    public static void ensureAuthorization(String topic, String user, AclOperation operation) {
        while (true) {
            boolean hasPermission = KafkaUtil.checkAuthorization(topic, user, operation);
            logger.info("{} authorization: {}", topic, hasPermission);
            if (hasPermission) {
                break;
            }

            logger.info("wait 3s...");

            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                e.printStackTrace();
                logger.error("sleep error", e);
            }
        }

    }

    public static synchronized boolean checkAuthorization(String topic, String user, AclOperation aclOperation) {
        String key = topic + user + aclOperation.name();
        if (cache.containsKey(key)) {
            boolean hasPermission = cache.get(key);
            if (hasPermission) {
                return true;
            }
        }

        if (kafkaAdminClient == null) {
            Properties properties = new Properties();
            properties.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, kafkaBrokerServer);

            properties.put("security.protocol", "SASL_PLAINTEXT");
            properties.put("sasl.mechanism", "PLAIN");
            properties.put("sasl.jaas.config", getAdminCypher());
            kafkaAdminClient = KafkaAdminClient.create(properties);
        }

        ResourcePatternFilter resourcePatternFilter = new ResourcePatternFilter(ResourceType.TOPIC, topic, PatternType.LITERAL);
        DescribeAclsOptions describeAclsOptions = new DescribeAclsOptions().timeoutMs(100000);
        AccessControlEntryFilter accessControlEntryFilter = new AccessControlEntryFilter("User:" + user, "*", aclOperation, AclPermissionType.ALLOW);

        AclBindingFilter aclBindingFilter = new AclBindingFilter(resourcePatternFilter, accessControlEntryFilter);
        DescribeAclsResult describeAclsResult = kafkaAdminClient.describeAcls(aclBindingFilter, describeAclsOptions);
        try {
            Collection<AclBinding> collection = describeAclsResult.values().get();
            collection.forEach(aclBinding -> logger.info(aclBinding.toString()));
            boolean hasPermission = !collection.isEmpty();
            cache.put(key, hasPermission);
            return hasPermission;
        } catch (InterruptedException e) {
            logger.error("get authorization error", e);
        } catch (ExecutionException e) {
            logger.error("get authorization error", e);
        }
        return false;
    }
}
