package NU.ETWRealTimeDetector.IPC;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.HostOperationMode;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import NU.ETWRealTimeDetector.Util.KafkaUtil;
import com.google.gson.Gson;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Reporter {
    private static final String kafkaTopic = SysConfig.getString("EventTopic", "event");
    private static final String kafkaBootStrapServer = SysConfig.getString("KafkaBrokerServer");
    private static final String ack = SysConfig.getString("ack", "0");
    private static final String retries = SysConfig.getString("retries", "3");
    private static final int max_in_flight_requests_per_connection = SysConfig.getInteger("MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION", 1);
    private static boolean sasl = SysConfig.getBoolean("SASL", false);
    private static final Logger eventLogger = LoggerFactory.getLogger("event");

    private static ExecutorService pool = Executors.newSingleThreadExecutor();
    private static Gson gson = new Gson();
    private static final Logger logger = LoggerFactory.getLogger(Reporter.class);
    private static final Logger honeyPotLogger = LoggerFactory.getLogger("honeypot");

    private static final boolean useLegacy = SysConfig.getBoolean("UseLegacy", false);

    private static Producer<String, String> _producer;

    public static void init() {
        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootStrapServer);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, "org.apache.kafka.common.serialization.StringSerializer");
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
        _producer = new KafkaProducer<>(props);

    }

    public static void reportResult(String clientID, Process process, String comment, String alertMode, String networkInfoJson, Map<String, Object> args, String eventId) {

        Date date = new Date(System.currentTimeMillis());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
        String beijingTime = dateFormat.format(date);

        Map<String, Object> result = new HashMap<>();
        result.put("id", eventId);
        result.put("log_name", alertMode);
        result.put("log_category", "Process");
        result.put("event", true);
        result.put("event_category", "Malicious");
        result.put("level", 3);// 中危
        result.put("result", 0);//
        result.put("operating", "");
        result.put("terminate", 1);// 告警
        result.put("host_name", "");
        result.put("ip_address", ProcessTable.getInstance(clientID).getIp());
        result.put("mac", "");
        result.put("uuid", ProcessTable.getInstance(clientID).getUuid());
        result.put("user", "");
        result.put("os_type", 1);
        result.put("os_version", "Windows");
        result.put("operation_mode", HostOperationMode.getHostOperationMode(ProcessTable.getInstance(clientID).getUuid()));// 正常模式
        long now = System.currentTimeMillis();
        result.put("timestamp", now);
        result.put("policy_id", 0);
        result.put("behavior", 1);// 异常行为
        result.put("source", "EDR");
        result.put("attck_tactics", "");
        result.put("attck_techniques", "");

        Map<String, Object> event_data = new HashMap<>();
        String processUuid = UUID.nameUUIDFromBytes(String.valueOf(process.getUuid()).getBytes()).toString();
        event_data.put("process_uuid", processUuid);
        event_data.put("process_id", process.getProcessId());
        event_data.put("process_name", process.getFileName());
        event_data.put("process_path", process.hasProcessName() ? process.getProcessName() : process.getFileName());
        event_data.put("process_commandline", process.getCommandLine());
        event_data.put("md5", process.getMd5());
        event_data.put("sha256", "");
        event_data.put("label", comment);
        event_data.put("attack_graph", "");
        event_data.put("process_tree", "");
        event_data.put("network_info", networkInfoJson);

        Map<Integer, ProcessNode> processNodeMap = DetectionFramework.getInstance(clientID).getProcessMap();
        ProcessNode processNode = processNodeMap.get(process.getUuid());

        String parentProcessUuid = "";
        Integer parentProcessId = 0;
        String parentProcessName = "";
        String parentProcessPath = "";
        String parentProcessCommandLine = "";
        String parentProcessMd5 = "";
        String parentProcessUser = "";

        if (processNode != null) {
            ProcessNode parentProcessNode = processNode.getParentNode();
            if (parentProcessNode != null) {
                parentProcessUuid = UUID.nameUUIDFromBytes(String.valueOf(parentProcessNode.getUuid()).getBytes()).toString();
                parentProcessId = parentProcessNode.getProcess().getProcessId();
                parentProcessName = parentProcessNode.getProcess().getFileName();
                parentProcessPath = parentProcessNode.getProcess().hasProcessName() ? parentProcessNode.getProcess().getProcessName() : parentProcessNode.getProcess().getFileName();;
                parentProcessCommandLine = parentProcessNode.getProcess().getCommandLine();
            }
        }

        event_data.put("parent_process_uuid", parentProcessUuid);
        event_data.put("parent_process_id", parentProcessId);
        event_data.put("parent_process_name", parentProcessName);
        event_data.put("parent_process_path", parentProcessPath);
        event_data.put("parent_process_commandline", parentProcessCommandLine);
        event_data.put("parent_process_md5", parentProcessMd5);
        event_data.put("parent_process_user", parentProcessUser);
        event_data.put("work_directory", parentProcessPath);
        event_data.put("closed_time", 0L);
        event_data.put("update_time", now);
        if (args != null) {
            event_data.putAll(args);
        }

        result.put("arguments", event_data);

        String json = gson.toJson(result);

        eventLogger.info("reportResult:{}", json);
        if (CompilationConfig.DEBUG) {
            return;
        }

        pool.execute(new KafkaReportMessage(kafkaTopic, json));
    }


    public static void reportEventToKafka(String topic, String json) {
        pool.execute(new KafkaReportMessage(topic, json));
    }

    public static void reportAttackGraphToKafka(String id, String type, String jsonGraph) {
        Map<String, Object> data = new HashMap<>();
        data.put("id", id);
        data.put("type", type);
        data.put("jsonGraph", jsonGraph);

        String json = gson.toJson(data);
        pool.execute(new KafkaReportMessage(kafkaTopic, json));
    }

    public static void monitorReportResult(String clientID, Process process, String comment, double maliciousScore, double confidenceScore, int alertLevel) {
        Date date = new Date(System.currentTimeMillis());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
        String beijingTime = dateFormat.format(date);

        Map<String, String> detectionResult = new HashMap<>();
        detectionResult.put("action", "monitor_report_result");
        detectionResult.put("clientID", clientID);
        detectionResult.put("appPath", process.getProcessName());
        detectionResult.put("processID", String.valueOf(process.getProcessId()));
        detectionResult.put("timestamp", beijingTime);
        detectionResult.put("phf", comment);
        detectionResult.put("maliciousScore", String.valueOf(maliciousScore));
        detectionResult.put("confidenceScore", String.valueOf(confidenceScore));
        detectionResult.put("alertLevel", String.valueOf(alertLevel));
        //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
    }

    public static void reportMacro(String clientId, String fileName, String md5) {
        pool.execute(() -> {
            Date date = new Date(System.currentTimeMillis());
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
            String beijingTime = dateFormat.format(date);
            Map<String, String> detectionResult = new HashMap<>();
            detectionResult.put("action", "report_macro");
            detectionResult.put("clientID", clientId);
            detectionResult.put("timestamp", beijingTime);
            detectionResult.put("fileName", fileName);
            detectionResult.put("macro", getMacroContentFilePath(clientId, md5));

            if (CompilationConfig.DEBUG) {
                return;
            }

            //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
        });
    }


    public static void reportGraph(String clientId, String pid, String uuid, String processName) {
        pool.execute(() -> {
            //draw attack
            //DrawAttackGraph attackDrawer = new DrawAttackGraph();
            //attackDrawer.draw(process);

            //draw process relation
            //DrawProcessRelation processRelation = new DrawProcessRelation();
            //processRelation.draw(process);

            Date date = new Date(System.currentTimeMillis());
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
            String beijingTime = dateFormat.format(date);
            Map<String, String> detectionResult = new HashMap<>();
            detectionResult.put("action", "report_graph");
            detectionResult.put("clientID", clientId);
            detectionResult.put("appPath", processName);
            detectionResult.put("processID", pid);
            detectionResult.put("timestamp", beijingTime);
            detectionResult.put("dot1", getAttackGraphFileName(clientId, pid, uuid, ""));
            detectionResult.put("dot2", getProcessRelationFileName(clientId, pid, uuid, ""));
            detectionResult.put("related_ip", getIpInfoFileName(clientId, pid, uuid));

            if (CompilationConfig.DEBUG) {
                return;
            }

            //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
        });
    }

    public static void reportRansomware(String eventId, String clientId, int processId, int parentProcessId, String processName, String processPath, String commandLine, String md5, String parentProcessName, String extraInfo, Long timestamp) {
        Map<String, Object> result = new HashMap<>();
        result.put("id", eventId);
        result.put("log_name", "Ransomeware");
        result.put("log_category", "File");
        result.put("event", true);
        result.put("event_category", "Malicious");
        result.put("level", 4);
        result.put("behavior", 1);// 异常行为
        result.put("result", 1);
        result.put("operating", "");
        result.put("terminate", 1);
        result.put("host_name", "");
        result.put("ip_address", ProcessTable.getInstance(clientId).getIp());
        result.put("mac", "");
        result.put("uuid", ProcessTable.getInstance(clientId).getUuid());
        result.put("user", "");
        result.put("os_type", 1);
        result.put("os_version", "Windows");
        long now = System.currentTimeMillis();
        result.put("timestamp", now);
        result.put("policy_id", 0);
        result.put("source", "EDR");
        result.put("operation_mode", HostOperationMode.getHostOperationMode(ProcessTable.getInstance(clientId).getUuid()));// 正常模式
        result.put("attck_tactics", "");
        result.put("attck_techniques", "");

        Map<String, Object> event_data = new HashMap<>();
        String processUuid = UUID.nameUUIDFromBytes(String.valueOf(processId).getBytes()).toString();
        event_data.put("process_id", processId);
        event_data.put("process_name", processName);
        event_data.put("process_path", processPath);
        event_data.put("process_commandline", commandLine);
        event_data.put("work_directory", "");
        event_data.put("user", "");
        event_data.put("md5", md5);
        event_data.put("filename", "");
        event_data.put("filepath", "");
        event_data.put("size", "");
        event_data.put("extension", "");
        event_data.put("new_filepath", "");
        event_data.put("ransomeware_detection_type", "AI");

        result.put("arguments", event_data);
        String json = gson.toJson(result);
        eventLogger.info("reportRansomeSomewareResult:{}", json);
        if (CompilationConfig.DEBUG) {
            return;
        }
        pool.execute(new KafkaReportMessage(kafkaTopic, json));
    }

    public static void reportSensitiveProgram(String clientId, String ppid, String uuid, String processName, String pid, String sensitiveProgram, String count) {
        Date date = new Date(System.currentTimeMillis());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
        String beijingTime = dateFormat.format(date);

        Map<String, String> reportParam = new HashMap<>();
        reportParam.put("action", "report_sensitiveprogram");
        reportParam.put("clientId", clientId);
        reportParam.put("ppid", ppid);
        reportParam.put("processName", processName);
        reportParam.put("pid", pid);
        reportParam.put("sensitiveProgram", sensitiveProgram);
        reportParam.put("timestamp", beijingTime);
        reportParam.put("count", count);
        reportParam.put("dot2", getSensitiveProgramProcessRelationFileName(clientId, ppid, uuid, pid));

        if (CompilationConfig.DEBUG) {
            return;
        }
        //pool.execute(new ReportMessage(gson.toJson(reportParam)));
    }

    public static void reportCryptoMining(String clientId, Process process, String ioc, Long timestamp) {
        Date date = new Date(System.currentTimeMillis());
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT+8"));
        String beijingTime = dateFormat.format(date);
        Map<String, String> detectionResult = new HashMap<>();
        detectionResult.put("action", "report_mining");
        detectionResult.put("clientID", clientId);
        detectionResult.put("time_stamp", timestamp.toString());
        detectionResult.put("ioc", ioc);
        detectionResult.put("process_path", process.getProcessName());
        detectionResult.put("process_name", getFileName(process.getProcessName()));
        detectionResult.put("pid", String.valueOf(process.getProcessId()));

        if (CompilationConfig.DEBUG) {
            return;
        }

        //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
    }

    public static void reportThreatIntelligence(List<HashMap<String, String>> list) {
        if (list.isEmpty()) {
            return;
        }

        Map<String, Object> detectionResult = new HashMap<>();
        detectionResult.put("action", "report_threatintelligence");
        detectionResult.put("data", list);

        if (CompilationConfig.DEBUG) {
            return;
        }

        //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
    }

    public static void reportRuleMatch(List<HashMap<String, String>> list) {
        if (list.isEmpty()) {
            return;
        }

        Map<String, Object> detectionResult = new HashMap<>();
        detectionResult.put("action", "report_rulematch");
        detectionResult.put("data", list);

        if (CompilationConfig.DEBUG) {
            return;
        }

        //pool.execute(new ReportMessage(gson.toJson(detectionResult)));
    }

    public static void reportDeviceRemoveable(String clientId, String serialNumber, String rootPath, String volumneName, String fileSystem, Long timestamp) {
        Map<String, String> params = new HashMap<>();
        params.put("action", "report_deviceremoveable");
        params.put("client_id", clientId);
        params.put("serial_number", serialNumber);
        params.put("root_path", rootPath);
        params.put("volume_name", volumneName);
        params.put("file_system", fileSystem);
        params.put("time_stamp", timestamp.toString());

        if (CompilationConfig.DEBUG) {
            return;
        }

        //pool.execute(new ReportMessage(gson.toJson(params)));
    }

    public static void reportNetwork(String clientId, Process process, String saddr, Integer sport, String daddr, Integer dport, String protocol, long count, Long timestamp) {
        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_network");
        params.put("eventType", "1");// 端口被访问
        params.put("clientID", clientId);
        params.put("timestamp", timestamp.toString());
        params.put("pid", String.valueOf(process.getProcessId()));
        String appPath = process.hasProcessName() ? process.getProcessName() : process.getFileName();
        params.put("appPath", appPath);
        params.put("saddr", saddr);
        params.put("sport", String.valueOf(sport));
        params.put("daddr", daddr);
        params.put("dport", String.valueOf(dport));
        params.put("protocol", protocol);
        params.put("count", String.valueOf(count));

        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }


    public static void reportUserLogonSuccess(String clientId,
                                              String logonType,
                                              Integer pid,
                                              String appPath,
                                              String targetUserName,
                                              String targetDomainName,
                                              String subjectUserName,
                                              String subjectDomainName,
                                              String workStationName,
                                              String ip,
                                              String port,
                                              Long timestamp) {
        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_userlogonsuccess");
        params.put("eventType", "2");// 用户登录成功
        params.put("clientID", clientId);
        params.put("pid", String.valueOf(pid));
        params.put("appPath", appPath);
        params.put("timestamp", timestamp.toString());
        params.put("logonType", logonType);
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("subjectUserName", subjectUserName);
        params.put("subjectDomainName", subjectDomainName);
        params.put("workStationName", workStationName);
        params.put("ipAddress", ip);
        params.put("ipPort", port);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportUserLogonFailed(String clientId,
                                             String logonType,
                                             Integer pid,
                                             String appPath,
                                             String targetUserName,
                                             String targetDomainName,
                                             String subjectUserName,
                                             String subjectDomainName,
                                             String workStationName,
                                             String ip,
                                             String port,
                                             String status,
                                             Long timestamp) {
        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_userlogonfailed");
        params.put("eventType", "3");// 用户登录失败
        params.put("clientID", clientId);
        params.put("pid", String.valueOf(pid));
        params.put("appPath", appPath);
        params.put("timestamp", timestamp.toString());
        params.put("logonType", logonType);
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("subjectUserName", subjectUserName);
        params.put("subjectDomainName", subjectDomainName);
        params.put("workStationName", workStationName);
        params.put("ipAddress", ip);
        params.put("ipPort", port);
        params.put("status", status);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportUserLogOff(String clientId,
                                        String targetUserName,
                                        String targetDomainName,
                                        String logonType,
                                        Long timestamp) {
        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_userlogoff");
        params.put("eventType", "4");// 用户注销
        params.put("clientID", clientId);
        params.put("timestamp", timestamp.toString());
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("logonType", logonType);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportExternalIp(List<HashMap<String, String>> list) {
        if (list.isEmpty()) {
            return;
        }
        HashMap<String, String> first = list.stream().findFirst().get();

        HashMap<String, Object> params = new HashMap<>();
        params.put("action", "report_externalip");
        params.put("eventType", "5");// 蜜罐机IP外连
        params.put("clientID", first.get("clientID"));
        params.put("timestamp", first.get("timestamp"));
        params.put("data", list);

        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportCreateUser(String clientId,
                                        String targetUserName,
                                        String targetDomainName,
                                        String subjectUserName,
                                        String subjectDomainName,
                                        Long timestamp) {

        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_createuser");
        params.put("eventType", "6");// 创建用户
        params.put("clientID", clientId);
        params.put("timestamp", timestamp.toString());
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("subjectUserName", subjectUserName);
        params.put("subjectDomainName", subjectDomainName);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportDeleteUser(String clientId,
                                        String targetUserName,
                                        String targetDomainName,
                                        String subjectUserName,
                                        String subjectDomainName,
                                        Long timestamp) {

        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_deleteuser");
        params.put("eventType", "7");// 删除用户
        params.put("clientID", clientId);
        params.put("timestamp", timestamp.toString());
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("subjectUserName", subjectUserName);
        params.put("subjectDomainName", subjectDomainName);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    public static void reportChangeUserPassword(String clientId,
                                                String targetUserName,
                                                String targetDomainName,
                                                String subjectUserName,
                                                String subjectDomainName,
                                                Long timestamp) {

        HashMap<String, String> params = new HashMap<>();
        params.put("action", "report_changeuserpassword");
        params.put("eventType", "8");// 修改密码
        params.put("clientID", clientId);
        params.put("timestamp", timestamp.toString());
        params.put("targetUserName", targetUserName);
        params.put("targetDomainName", targetDomainName);
        params.put("subjectUserName", subjectUserName);
        params.put("subjectDomainName", subjectDomainName);
        String json = gson.toJson(params);
        //reportHoneyPot(json);
    }

    private static void reportHoneyPot(String json) {
        if (CompilationConfig.DEBUG) {
            return;
        }

        honeyPotLogger.info(json);
        pool.execute(new ReportMessage(json));
    }

    private static String getFileName(String processName) {
        if (processName == null || processName.isEmpty()) {
            return "";
        }

        int lastIndexOfCharacter = processName.lastIndexOf("\\");
        if (lastIndexOfCharacter < 0) {
            return processName;
        }

        return processName.substring(lastIndexOfCharacter + 1);
    }

    public static String getSensitiveProgramProcessRelationFileName(String clientId, String ppid, String pid, String uuid) {
        return String.format("graph/%s/ppid_%s_uuid_%s_pid_%s_SensitiveProgram_Relation.json", clientId, ppid, uuid, pid);
    }

    public static String getProcessRelationFileName(String clientId, String pid, String uuid, String eventId) {
        if (useLegacy) {
            return String.format("dot/%s/pid_%s_uuid_%s_Relation.dot", clientId, pid, uuid);
        } else {
            return String.format("graph/%s/pid_%s_uuid_%s_eventId_%s_Relation.json", clientId, pid, uuid, eventId);
        }
    }

    public static String getAttackGraphFileName(String clientId, String pid, String uuid, String eventId) {
        if (useLegacy) {
            return String.format("dot/%s/pid_%s_uuid_%s.dot", clientId, pid, uuid);
        } else {
            return String.format("graph/%s/pid_%s_uuid_%s_eventId_%s.json", clientId, pid, uuid, eventId);
        }
    }

    public static String getIpInfoFileName(String clientId, String pid, String uuid) {
        return String.format("graph/%s/pid_%s_uuid_%s_ip.json", clientId, pid, uuid);
    }

    public static String getMacroContentFilePath(String clientId, String md5) {
        return String.format("macroContent/%s/%s", clientId, md5);
    }


    private static class ReportMessage implements Runnable {

        private final String message;

        ReportMessage(String message) {
            this.message = message;
        }

        @Override
        public void run() {
        }
    }

    private static class KafkaReportMessage implements Runnable {

        private final String message;
        private final String topic;

        KafkaReportMessage(String topic, String message) {
            this.topic = topic;
            this.message = message;
        }

        @Override
        public void run() {
            ProducerRecord<String, String> record = new ProducerRecord<>(topic, message);
            _producer.send(record, (metaData, e) -> {
                if (e != null) {
                    eventLogger.error("send event to kafka error", e);
                }
                if (metaData.hasOffset()) {
                    eventLogger.info("send success to {}. offset {} message {}", metaData.topic(), metaData.offset(), metaData);
                } else {
                    eventLogger.error("send event to kafka error");
                }
            });

        }
    }


}
