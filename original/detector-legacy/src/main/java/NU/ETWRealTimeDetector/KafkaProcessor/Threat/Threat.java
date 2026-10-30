package NU.ETWRealTimeDetector.KafkaProcessor.Threat;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.HostOperationMode;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sqlite.SQLiteConfig;
import redis.clients.jedis.Jedis;

import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.Arrays.asList;

public class Threat {

    private static final Logger logger = LoggerFactory.getLogger("ioc");
    private static String centerUrl = SysConfig.getString("CenterUrl", "localhost:8899");
    private static String trustIpListApi = SysConfig.getString("TrustIpListApi", "/api/policy/rule/trust/ip");
    private static ConcurrentHashMap<String, Ioc> localIocMap = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String, Ioc> customIocMap = new ConcurrentHashMap<>();
    private static final List<String> keys = asList("md5", "sha256", "daddr", "remote_ip", "destination_ip", "domain", "sha1");
    private static final List<String> ensureIocKeys = asList("ioc", "ioc_type", "severity", "label", "threat_type", "ioc_source", "ioc_code");
    private static final ConcurrentHashMap<String, Object> initArgs = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Integer, String> threatType2LogName = new ConcurrentHashMap<>();
    private static Setting setting = Setting.defaultSetting();
    private static long updateTime;
    private static Connection connection;
    private static PreparedStatement prep;
    private static List<String> trustIpList = new CopyOnWriteArrayList<>();
    private static Gson gson = new Gson();


    public static void init() {
        String settingStr = "";
        String iocStr = "";
        try (Jedis jedis = JedisPoolUtil.getJedis()) {
            // 加载配置
            settingStr = jedis.get("threat:setting");
            // 加载规则
            iocStr = jedis.get("threat:ioc");
        } catch (Exception e) {
            logger.error("redis error", e);
        }

        ObjectMapper objectMapper = new ObjectMapper();
        if (StringUtils.isNotEmpty(settingStr)) {
            try {
                setting = objectMapper.readValue(settingStr, Setting.class);
                logger.info("threat setting local: {} custom: {}", setting.getLocal(), setting.getCustom());
            } catch (Exception e) {
                logger.error("threat setting deserialization error", e);
                setting = Setting.defaultSetting();
            }
        }

        TypeReference<List<HashMap<String, Object>>> typeRef = new TypeReference<List<HashMap<String, Object>>>() {
        };
        List<HashMap<String, Object>> list = new ArrayList<>();

        if (StringUtils.isNotEmpty(iocStr)) {
            try {
                list = objectMapper.readValue(iocStr, typeRef);
            } catch (Exception e) {
                logger.error("threat ioc deserialization error", e);
            }
        }

        localIocMap.clear();
        customIocMap.clear();
        for (Map<String, Object> map : list) {
            // 校验IOC参数
            if (!checkIoc(map)) {
                continue;
            }
            Ioc ioc = new Ioc();
            ioc.setIoc(map.getOrDefault("ioc", "").toString());
            ioc.setIocType((Integer) map.get("ioc_type"));
            ioc.setSeverity((Integer) map.get("severity"));
            ioc.setLabel(map.get("label").toString());
            ioc.setThreatType((Integer) map.get("threat_type"));
            ioc.setIocSource((Integer) map.get("ioc_source"));
            ioc.setIocCode(map.getOrDefault("ioc_code", "").toString());
            ioc.setHashType((Integer) map.get("hash_type"));
            if (ioc.getIocSource().equals(1)) {
                // 本地，ioc参数值全小写，能让数据更好地匹配到
                localIocMap.put(ioc.getIoc().toLowerCase(), ioc);
            } else {
                // 自定义，ioc参数值全小写，能让数据更好地匹配到
                customIocMap.put(ioc.getIoc().toLowerCase(), ioc);
            }
        }

        initArgs.clear();
        initArgs.put("process_uuid", "");
        initArgs.put("process_id", -1);
        initArgs.put("process_name", "");
        initArgs.put("process_path", "");
        initArgs.put("process_commandline", "");
        initArgs.put("parent_process_uuid", "");
        initArgs.put("parent_process_id", -1);
        initArgs.put("parent_process_name", "");
        initArgs.put("parent_process_path", "");
        initArgs.put("parent_process_commandline", "");
        initArgs.put("parent_process_md5", "");
        initArgs.put("parent_process_user", "");
        initArgs.put("work_directory", "");
        initArgs.put("md5", "");
        initArgs.put("file_md5", "");
        initSqliteConnection();
        refreshTrustList();
    }

    private static void refreshTrustList() {
        try {

            HttpRequest request = HttpRequest.get(centerUrl + trustIpListApi);
            if (request.code() != 200) {
                return;
            }
            String json = request.body();

            Map<String, Object> map = gson.fromJson(json, Map.class);
            if (!map.containsKey("data")) {
                return;
            }
            List<String> ipList = (List<String>) map.getOrDefault("data", new ArrayList<>());
            trustIpList.clear();
            trustIpList.addAll(ipList);
        } catch (Exception e) {
            logger.error("refreshTrustList error", e);
        }
    }

    private static void initSqliteConnection() {
        if (connection != null) {
            return;
        }
        SQLiteConfig config = new SQLiteConfig();
        config.setReadOnly(true);
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:ioc.db", config.toProperties());
            connection.setAutoCommit(false);
            prep = connection.prepareStatement("select * from tb_ioc where data = ? and status=1 limit 1");
        } catch (SQLException e) {
            logger.error("sqlite get connection error", e);
        }
    }

    private static Ioc checkLocalIoc(String value) {
        if (prep == null) {
            return null;
        }
        ResultSet rs = null;
        try {
            prep.setString(1, value);
            rs = prep.executeQuery();
            if (rs.next()) {
                String iocCode = rs.getString("id");
                String iocType = rs.getString("ioc_type");
                String ioc = rs.getString("data");
                Ioc model = new Ioc();
                model.setIoc(ioc);
                model.setIocCode(iocCode);
                // 默认4 高危
                model.setSeverity(4);
                // 1 本地库
                model.setIocSource(1);
                // ioc类型
                model.setIocType(getIocType(iocType));
                // 威胁类型
                model.setThreatType(getThreatTypeByIocType(model.getIocType()));
                model.setLabel("");

                if (model.getIocType().equals(0)) {
                    return null;
                }
                return model;
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("check local ioc error", e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    logger.error("ResultSet close fail: {}", e.getMessage());
                }
            }
        }
        return null;
    }


    private static Integer getThreatTypeByIocType(Integer iocType) {
        if (iocType.equals(1)) {
            // 恶意软件
            return 1;
        } else if (iocType.equals(2)) {
            // 恶意IP
            return 2;
        } else if (iocType.equals(3)) {
            // 恶意域名
            return 3;
        }
        return 0;
    }

    private static Integer getIocType(String iocType) {
        // domain 08aa2c3f.space
        //email catherina@outlook.com
        //hash 863515f37d833c2a83576dfd0fc38985
        //ip 148.66.138.116
        //url http://parisyoungerfashion.com/.ok/need/work/Panel/five/PvqDq929BSx_A_D_M1n_a.php

        if (iocType.equals("hash")) {
            return 1;
        } else if (iocType.equals("ip")) {
            return 2;
        } else if (iocType.equals("domain")) {
            return 3;
        }
        return 0;
    }

    private static boolean checkIoc(Map<String, Object> map) {
        if (map == null) {
            return false;
        }
        if (map.isEmpty()) {
            return false;
        }

        return ensureIocKeys.stream().allMatch(key -> map.containsKey(key));
    }

    public static void updateSetting() {
        long current = System.currentTimeMillis();
        // 1分钟更新一次
        if (current - updateTime < 60000) {
            return;
        }
        try {
            Threat.init();
            logger.info("update threat setting {}", current);
        } catch (Exception e) {
            logger.error("update setting error", e);
        } finally {
            updateTime = current;
        }
    }

    public static void check(Map<String, Object> log) {
        try {
            updateSetting();
            if (log == null || log.isEmpty()) {
                return;
            }

            if (!log.containsKey("arguments")) {
                return;
            }

            Object obj = log.get("arguments");
            if (!(obj instanceof Map)) {
                return;
            }

            Map<String, Object> args = (Map<String, Object>) obj;

            for (String key : keys) {
                if (!args.containsKey(key)) {
                    continue;
                }

                String value = args.get(key).toString().toLowerCase();
                if (setting.getLocal()) {
                    // 排除可信名单
                    if (!trustIpList.contains(value)) {
                        // 本地威胁情报库匹配
                        Ioc ioc = checkLocalIoc(value);
                        if (ioc != null) {
                            reportThreatEvent(log, args, ioc);
                        }
                    }
                }
                if (setting.getCustom()) {
                    if (customIocMap.containsKey(value)) {
                        // 上报威胁情报事件
                        Ioc ioc = customIocMap.get(value);
                        reportThreatEvent(log, args, ioc);
                    }
                }
            }

        } catch (Exception e) {
            logger.error("threat error ", e);
        }
    }

    private static void reportThreatEvent(Map<String, Object> log, Map<String, Object> logArguments, Ioc ioc) {

        HashMap<String, Object> event = new HashMap<>();
        event.put("id", UUID.randomUUID().toString());
        event.put("log_name", getLogName(ioc.getThreatType()));
        event.put("log_category", "ThreatIntelligence");
        event.put("event", true);
        event.put("event_category", "ThreatIntelligence");
        // 威胁情报默认为高危
        event.put("level", 4);

        event.put("behavior", 1);
        // 动作 无
        event.put("operating", "");
        // 默认 告警
        event.put("terminate", 1);
        // 结果 无
        event.put("result", 0);
        event.put("host_name", log.getOrDefault("host_name", ""));
        event.put("mac", log.getOrDefault("mac", ""));
        event.put("uuid", log.getOrDefault("uuid", ""));
        event.put("ip_address", log.getOrDefault("ip_address", ""));
        event.put("ipv6_address", log.getOrDefault("ipv6_address", ""));
        event.put("user", log.getOrDefault("user", ""));
        event.put("os_type", log.getOrDefault("os_type", ""));
        event.put("os_version", log.getOrDefault("os_version", ""));
        event.put("policy_id", log.getOrDefault("policy_id", ""));
        event.put("source", "ThreatIntelligence");
        event.put("attck_tactics", "");
        event.put("attck_techniques", "");
        event.put("timestamp", log.getOrDefault("timestamp", System.currentTimeMillis()));
        event.put("operation_mode", HostOperationMode.getHostOperationMode(log.getOrDefault("uuid", "").toString()));
        HashMap<String, Object> arguments = new HashMap<>();
        event.put("arguments", arguments);

        // 补全参数
        transKey(logArguments, arguments);

        String refId = log.getOrDefault("id", "").toString();

        // 补全其余参数

        // 关联日志id
        arguments.put("ref_id", refId);

        // 情报IOC
        arguments.put("ioc", ioc.getIoc());

        // 情报类型 Hash/IP/Domain
        arguments.put("ioc_type", ioc.getIocType());

        // hash类型 md5/sha1/sha256
        arguments.put("hash_type", ioc.getHashType());

        // 情报IOC 严重性
        arguments.put("ioc_severity", ioc.getSeverity());

        // 威胁类型 File/IP/Domain
        arguments.put("threat_type", ioc.getThreatType());

        // 情报来源 本地库 Local、Custom、ThirdParty
        arguments.put("ioc_source", ioc.getIocSource());

        // 情报标签
        arguments.put("ioc_label", ioc.getLabel());

        // 情报IOC 唯一标识，同一个情报 修改后会生成新的唯一标识，情报捕获页面会重新计数
        arguments.put("ioc_code", ioc.getIocCode());

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(event);
            Reporter.reportEventToKafka("event", json);
            logger.info("ioc: {} log:{} event:{}", ioc.getIoc(), log, event);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }

    private static void transKey(Map<String, Object> logArguments, HashMap<String, Object> arguments) {
        for (Map.Entry<String, Object> entry : initArgs.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            arguments.put(key, logArguments.getOrDefault(key, value));
        }
    }

    private static String getLogName(Integer threatType) {
        String logName = "";
        switch (threatType) {
            case 1:
                logName = "ThreatFile";
                break;
            case 2:
                logName = "ThreatIP";
                break;
            case 3:
                logName = "ThreatDomain";
                break;
            default:
                break;
        }
        return logName;
    }
}