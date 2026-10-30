package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.mysql.jdbc.exceptions.jdbc4.CommunicationsException;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.math.BigDecimal;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;
import java.util.concurrent.LinkedBlockingQueue;


/**
 * @author pengtengCao
 * @date Created in 2021/5/18 17:58
 * @description：
 */
public class EventGroupProcessor extends Thread {

    private static final Logger logger = LoggerFactory.getLogger("event_group");
    private static LinkedBlockingQueue<Map<String, String>> linkedBlockingQueue = new LinkedBlockingQueue<>();

    private static ConnectionPool connPool = new ConnectionPool(
            "com.mysql.jdbc.Driver"
            , "jdbc:mysql://" + SysConfig.getString("MysqlHost") + "/cornerstone?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai"
            , SysConfig.getString("MysqlUsername")
            , SysConfig.getString("MysqlPassword"));


    public EventGroupProcessor() {

    }


    @Override
    public void run() {
        while (true) {
            try {
                Map<String, String> poll = linkedBlockingQueue.poll();
                if (null == poll || poll.size() == 0) {
                    Thread.sleep(1000);
                } else {
                    Connection conn = connPool.getConnection();
                    PreparedStatement preparedStatement = conn.prepareStatement(poll.get("sql"));
                    for (String key : poll.keySet()) {
                        if ("sql".equals(key)) {
                            continue;
                        }
                        // 12个参数是保存sql，其他是更新sql
                        if (poll.size() > 11) {
                            if ("3".equals(key) || "12".equals(key)) {
                                preparedStatement.setInt(Integer.parseInt(key), Integer.parseInt(poll.get(key)));
                            } else {
                                preparedStatement.setString(Integer.parseInt(key), poll.get(key));
                            }
                        } else {
                            if ("6".equals(key)) {
                                preparedStatement.setInt(Integer.parseInt(key), Integer.parseInt(poll.get(key)));
                            } else {
                                preparedStatement.setString(Integer.parseInt(key), poll.get(key));
                            }
                        }
                    }
                    preparedStatement.executeUpdate();
                    preparedStatement.close();
                    connPool.returnConnection(conn);
                }
            } catch (CommunicationsException e) {
                logger.error("数据库连接失败", e);
                try {
                    Thread.sleep(1000 * 60);
                } catch (InterruptedException interruptedException) {
                    interruptedException.printStackTrace();
                }
            } catch (Exception e) {
                logger.error("插入数据库失败", e);
            }
        }
    }

    /**
     * 事件主体
     */
    private static final Map<String, List<String>> EVENT_BODY = new HashMap<>();

    static {
        EVENT_BODY.put("Mining", Arrays.asList("process_name", "process_path", "mining_pool"));
        EVENT_BODY.put("Ransomeware", Arrays.asList("process_name", "process_path"));
        EVENT_BODY.put("IllegalNetwork", Arrays.asList("destination_ip", "process_name", "process_path"));
        EVENT_BODY.put("MBR", Arrays.asList("process_name", "process_path"));
        EVENT_BODY.put("ReverseShell", Arrays.asList("remote_ip", "parent_process_name", "process_name"));
        EVENT_BODY.put("FakeSystemProcess", Arrays.asList("process_name", "process_path"));
        EVENT_BODY.put("ServiceProcess", Arrays.asList("process_name", "process_path"));
        EVENT_BODY.put("IllegalLoginIp", Arrays.asList("remote_ip"));
        EVENT_BODY.put("IllegalLoginAccount", Arrays.asList("user"));
        EVENT_BODY.put("Crack", Arrays.asList("remote_ip"));
        EVENT_BODY.put("AntivirusProtection", Arrays.asList("filepath"));
        EVENT_BODY.put("RequestMaliciousDomain", Arrays.asList("domain"));
        // 敏感行为类事件
        List<String> sensitiveBehavior = Arrays.asList("process_name", "process_path", "filename", "filepath");
        EVENT_BODY.put("RegistryTamper", sensitiveBehavior);
        EVENT_BODY.put("IllegalDeleteLog", sensitiveBehavior);
        EVENT_BODY.put("MaliciousFile", sensitiveBehavior);
        EVENT_BODY.put("ExecutableFiles", sensitiveBehavior);
        EVENT_BODY.put("ScriptFiles", sensitiveBehavior);
        EVENT_BODY.put("IllegalScriptFiles", sensitiveBehavior);
        EVENT_BODY.put("Webshell_detect", sensitiveBehavior);
        EVENT_BODY.put("IllegalFileOperation", sensitiveBehavior);
        // 其他网络连接类事件
        List<String> illegalNetwork = Arrays.asList("remote_ip", "domain");
        EVENT_BODY.put("PortScan", illegalNetwork);
        EVENT_BODY.put("HoneyPort", illegalNetwork);
        EVENT_BODY.put("IllegalConnectInternet", illegalNetwork);
        // 进程异常行为类事件
        List<String> process = Arrays.asList("parent_process_name", "process_name", "process_path");
        EVENT_BODY.put("PrivilegeEscalation", process);
        EVENT_BODY.put("Webshell", process);
        EVENT_BODY.put("RiskCommand", process);
        EVENT_BODY.put("AbnormalProcess", process);
        EVENT_BODY.put("IllegalProcess", process);
    }


    public static String process(Map<String, Object> map) {
        boolean flag = map.containsKey("operation_mode") && Double.parseDouble(map.getOrDefault("operation_mode", "").toString()) > 1;
        if (flag) {
            return JSONObject.toJSONString(map);
        }
        String logCategory = map.getOrDefault("log_category", "").toString();
        if ("Device".equals(logCategory) || "SystemResource".equals(logCategory)) {
            return JSONObject.toJSONString(map);
        }
        try (Jedis jedis = JedisPoolUtil.getJedis()) {
            Map<String, Object> arguments = (Map<String, Object>) map.get("arguments");
            if (null == arguments) {
                return JSONObject.toJSONString(map);
            }

            String logName = map.getOrDefault("log_name", "").toString();
            String ipAddress = map.getOrDefault("ip_address", "").toString();
            String level = (int) Double.parseDouble(map.get("level").toString()) + "";
            String eventId = map.getOrDefault("id", "").toString();
            Object processUuid = arguments.get("process_uuid");
            Object parentProcessUuid = arguments.get("parent_process_uuid");
            Object md5 = arguments.get("file_md5");
            Object domain = arguments.get("domain");
            Object remoteIp = arguments.get("remote_ip");
            Object sessionUuid = arguments.get("session_uuid");
            String timestamp = new BigDecimal(map.get("timestamp").toString()).toPlainString();
            String eventGroupId = UUID.randomUUID().toString();
            String traceabilityMap = "";

            // 上级节点事件id
            String superior = "";
            // 关联字段
            String superiorField = "";
            // 关联字段值
            String superiorFieldValue = "";

            String globalLocalIpRedisKey = "event_group:local_ip";// 缓存受害者ip对应的事件组

            Map<String, String> tmp = new LinkedHashMap<>();

            if (ObjectUtils.isNotEmpty(processUuid)) {
                tmp.put("process_uuid", processUuid.toString());
            }
            if (ObjectUtils.isNotEmpty(parentProcessUuid)) {
                tmp.put("parent_process_uuid", parentProcessUuid.toString());
            }
            if (ObjectUtils.isNotEmpty(md5)) {
                tmp.put("md5", md5.toString().toLowerCase());
            }
            if (ObjectUtils.isNotEmpty(domain) && !"IllegalConnectInternet".equals(logName)) {
                tmp.put("domain", domain.toString());
            }
            if (ObjectUtils.isNotEmpty(remoteIp)) {
                tmp.put("remote_ip", remoteIp.toString());
            }
            if (ObjectUtils.isNotEmpty(sessionUuid)) {
                tmp.put("session_uuid", sessionUuid.toString());
            }

            if (tmp.size() == 0) {
                return JSONObject.toJSONString(map);
            }

            int exist = 0;
            for (String s : tmp.keySet()) {
                String key = String.format("event_group:%s", s);
                String value = tmp.get(s);
                if (jedis.hexists(key, value)) {
                    // 当满足这些条件时证明在关联元素里面找到了对应的事件组
                    exist = 1;
                    superiorField = s;
                    superiorFieldValue = value;
                    eventGroupId = jedis.hget(key, value);
                    break;
                }
                if ("remote_ip".equals(s)) {
                    // 如果没找到，则继续查找有没有远程ip对应到的受害者ip名单
                    if (jedis.hexists(globalLocalIpRedisKey, value)) {
                        exist = 2;
                        superiorField = s;
                        superiorFieldValue = value;
                        eventGroupId = jedis.hget(globalLocalIpRedisKey, value);
                        break;
                    }
                }
            }

            String eventGroupRedisKey = String.format("event_group:%s", eventGroupId);
            String eventGroupSuperiorRedisKey = String.format("event_group:%s:superior", eventGroupId);
            String eventGroupIpsRedisKey = String.format("event_group:%s:ips", eventGroupId);
            String eventGroupTypesRedisKey = String.format("event_group:%s:types", eventGroupId);
            String eventGroupLevelsRedisKey = String.format("event_group:%s:levels", eventGroupId);
            String eventGroupLocalIpRedisKey = String.format("event_group:%s:local_ip", eventGroupId);
            String eventGroupDistinctRedisKey = String.format("event_group:%s:distinct", eventGroupId);

            // 如果没有找到关联关系, 关联字段就是冒号
            String relationField = String.format("%s:%s", superiorField, superiorFieldValue);

            // 去重规则的组成部分是 ip地址、事件、关联元素、和事件主体(事件主体每个事件不一样)
            Map<String, Object> distinct = new LinkedHashMap<>();
            distinct.put("ip_address", ipAddress);
            distinct.put("log_name", logName);

            if (EVENT_BODY.containsKey(logName)) {
                List<String> params = EVENT_BODY.get(logName);
                for (String param : params) {
                    Object paramValue = arguments.get(param);
                    if(paramValue != null) {
                        distinct.put(param, paramValue);
                    }
                }
            }

            // 更新事件组
            updateRedis(jedis, eventGroupIpsRedisKey, ipAddress);
            updateRedis(jedis, eventGroupTypesRedisKey, logName);
            updateRedis(jedis, eventGroupLevelsRedisKey, level);

            Map<String, String> redisData = getDataFromRedis(jedis, eventGroupId);
            String ips = redisData.get("ips");
            String types = redisData.get("types");
            String levels = redisData.get("levels");
            String nums = redisData.get("nums");

            if (exist == 0) {
                // 事件组不存在，生成新的事件组
                for (String filed : tmp.keySet()) {
                    String globalRedisKey = String.format("event_group:%s", filed);
                    String filedValue = tmp.get(filed);
                    // 设置全局关联元素值对应的事件组信息
                    jedis.hset(globalRedisKey, filedValue, eventGroupId);
                    // 设置事件组关联元素对应的起点信息
                    jedis.hset(eventGroupSuperiorRedisKey, filed, eventId);
                }
                Map<String, String> superiorMap = jedis.hgetAll(eventGroupSuperiorRedisKey);
                traceabilityMap = "1";
                distinct.put("relation_field", relationField);
                eventDistinct(jedis, distinct, eventGroupDistinctRedisKey, eventId);
                addLocalIpToRelation(jedis, ipAddress, eventGroupId, remoteIp, tmp, eventId, globalLocalIpRedisKey, eventGroupLocalIpRedisKey);
                insertEventGroup(jedis, tmp, eventGroupRedisKey);
                linkedBlockingQueue.add(getInsertEventGroupSql(eventGroupId, JSON.toJSONString(tmp), JSON.toJSONString(superiorMap), timestamp, ips, types, levels, nums));
            } else {
                // 事件组存在，更新相关信息
                Map<String, String> eventGroupRelationFiled = jedis.hgetAll(String.format("event_group:%s", eventGroupId));
                if ("remote_ip".equals(superiorField)) {
                    if (2 == exist) {
                        // 受害者ip作为远端ip关联进来时，起点为更新该ip的事件
                        superior = jedis.hget(eventGroupLocalIpRedisKey, superiorFieldValue);
                        // 保存受害主机ip，只有被引用的受害主机才会保存
                        String localIp = eventGroupRelationFiled.get("local_ip");
                        List<String> localIpList;
                        if (localIp == null) {
                            localIpList = new ArrayList<>();
                        } else {
                            localIpList = JSON.parseArray(localIp, String.class);
                        }
                        if (!localIpList.contains(remoteIp.toString())) {
                            localIpList.add(remoteIp.toString());
                            localIp = JSON.toJSONString(localIpList);
                            eventGroupRelationFiled.put("local_ip", localIp);
                            jedis.hset(String.format("event_group:%s", eventGroupId), "local_ip", localIp);
                        }
                    }
                } else if (!"domain".equals(superiorField)) {
                    superior = jedis.hget(eventGroupSuperiorRedisKey, superiorField);
                    // 关联元素有多个时，看当前事件组哪个关联元素先进入事件组就用哪个关联元素
                    for (Map.Entry<String, String> entry : eventGroupRelationFiled.entrySet()) {
                        String key = entry.getKey();
                        if (tmp.containsKey(key)) {
                            String value = tmp.get(key);
                            String entryValue = entry.getValue();
                            if (value.equals(entryValue)) {
                                relationField = key + ":" + value;
                            }
                        }
                    }
                    distinct.put("relation_field", relationField);
                }

                // 去重
                String repeatEventId = eventDistinct(jedis, distinct, eventGroupDistinctRedisKey, eventId);
                if (StringUtils.isBlank(repeatEventId)) {
                    traceabilityMap = "1";
                } else {
                    // 事件组有同类型信息，1、判断有没有生成新的关联元素 有则把新增的关联元素对应的起点设置成返回的事件id
                    eventId = repeatEventId;
                }

                // 判断事件组中六个关联关系是否都存在
                for (String filed : tmp.keySet()) {
                    if (!eventGroupRelationFiled.containsKey(filed)) {
                        String globalRedisKey = String.format("event_group:%s", filed);
                        String filedValue = tmp.get(filed);
                        eventGroupRelationFiled.put(filed, filedValue);
                        jedis.hset(globalRedisKey, filedValue, eventGroupId);
                        jedis.hset(eventGroupSuperiorRedisKey, filed, eventId);
                        jedis.hset(eventGroupRedisKey, filed, filedValue);
                    }
                }
                Map<String, String> superiorMap = jedis.hgetAll(eventGroupSuperiorRedisKey);
                addLocalIpToRelation(jedis, ipAddress, eventGroupId, remoteIp, eventGroupRelationFiled, eventId, globalLocalIpRedisKey, eventGroupLocalIpRedisKey);
                linkedBlockingQueue.add(getUpdateEventGroupSql(eventGroupId, JSON.toJSONString(eventGroupRelationFiled), JSON.toJSONString(superiorMap),timestamp, ips, types, levels, nums));
            }
            map.put("traceability_map", traceabilityMap);
            map.put("event_group_id", eventGroupId);
            map.put("superior", superior);
            map.put("relation_field", relationField);
            return JSONObject.toJSONString(map);
        } catch (Exception e) {
            logger.error("事件组数据处理错误 {}", e.getMessage());
            return JSONObject.toJSONString(map);
        }
    }

    // 将本机ip作为受害者ip加入关联关系
    private static void addLocalIpToRelation(Jedis jedis,
                                             String ipAddress,
                                             String eventGroupId,
                                             Object remoteIp,
                                             Map<String, String> map,
                                             String eventId,
                                             String globalLocalIpKey,
                                             String eventGroupLocalIpRedisKey) {

        // 如果全局local_ip中不存在当前主机ip
        if (ObjectUtils.isNotEmpty(remoteIp) && StringUtils.isNotBlank(ipAddress) && !jedis.hexists(globalLocalIpKey, ipAddress)) {
            // 将本机ip加入到全局local_ip中，value是事件组id
            jedis.hset(globalLocalIpKey, ipAddress, eventGroupId);
            if (!jedis.hexists(eventGroupLocalIpRedisKey, ipAddress)) {
                // 将本机ip加入到事件组local_ip中
                jedis.hset(eventGroupLocalIpRedisKey, ipAddress, eventId);
            }
            // 将本机ip加入到事件组中
            map.put("remote_ip", String.format("%s,%s", map.get("remote_ip"), ipAddress));
        }
    }

    /**
     * 设置去重条件缓存
     * @return event_id 返回已存在的事件id
     */
    private static String eventDistinct(Jedis jedis, Map<String, Object> distinct, String eventGroupDistinctRedisKey, String eventId) {
        // 普通节点
        String commonNode = JSON.toJSONString(distinct);
        // 起始节点
        distinct.put("relation_field", ":");
        String startNode = JSON.toJSONString(distinct);
        String id = "";
        if (!jedis.hexists(eventGroupDistinctRedisKey, commonNode) && !jedis.hexists(eventGroupDistinctRedisKey, startNode)) {
            jedis.hset(eventGroupDistinctRedisKey, commonNode, eventId);
        } else {
            id = jedis.hget(eventGroupDistinctRedisKey, commonNode);
            if (StringUtils.isEmpty(id)) {
               id = jedis.hget(eventGroupDistinctRedisKey, startNode);
            }
        }
        return id;
    }


    // 更新事件组关联元素
    private static void insertEventGroup(Jedis jedis, Map<String, String> map, String eventGroupRedisKey) {
        for (String filed : map.keySet()) {
            String filedValue = map.get(filed);
            jedis.hset(eventGroupRedisKey, filed, filedValue);
        }
    }

    private static Map<String, String> getDataFromRedis(Jedis jedis, String eventGroupId) {
        Map<String, String> map = new HashMap<>();
        map.put("ips", getStr(jedis, eventGroupId, "ips"));
        map.put("types", getStr(jedis, eventGroupId, "types"));
        map.put("levels", getStr(jedis, eventGroupId, "levels"));
        map.put("nums", getNums(jedis, eventGroupId, "ips"));
        return map;
    }

    private static String getStr(Jedis jedis, String eventGroupId, String suffix) {
        String key = String.format("event_group:%s:%s", eventGroupId, suffix);
        Set<String> set = jedis.zrange(key, 0, -1);
        List<String> list = new ArrayList<>();
        for (String member : set) {
            int zscore = jedis.zscore(key, member).intValue();
            if ("levels".equals(suffix)) {
                list.add(String.format("%s", member, zscore));
            } else {
                list.add(String.format("%s ||| %d", member, zscore));
            }
        }
        return StringUtils.join(list.toArray(), ",");
    }

    private static String getNums(Jedis jedis, String eventGroupId, String suffix) {
        String key = String.format("event_group:%s:%s", eventGroupId, suffix);
        Set<String> set = jedis.zrange(key, 0, -1);
        int num = 0;
        for (String member : set) {
            num += jedis.zscore(key, member).intValue();
        }
        return num + "";
    }

    /**
     * 更新redis信息，
     *
     * @param jedis
     * @param key
     * @param member
     */
    private static void updateRedis(Jedis jedis, String key, String member) {
        if (jedis.zscore(key, member) != null) {
            jedis.zincrby(key, 1, member);
        } else {
            jedis.zadd(key, 1, member);
        }
    }

    private static Map<String, String> getInsertEventGroupSql(String eventGroupId, String relationEle, String relationSup, String timestamp,  String ips, String types, String levels, String nums) {
        Map<String, String> map = new HashMap<>();
        String sql = "INSERT INTO event_group (event_group_id, relation_ele, process_status, description, create_time, update_time, start_time, end_time, ips, types, levels, nums, relation_sup) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        map.put("1", eventGroupId);
        map.put("2", relationEle);
        map.put("3", "0");
        map.put("4", null);
        map.put("5", DateUtil.format(new Date(), DateUtil.PATTERN_DATE_TIME));
        map.put("6", DateUtil.format(new Date(), DateUtil.PATTERN_DATE_TIME));
        map.put("7", DateUtil.timeStamp2Date(Long.parseLong(timestamp), DateUtil.PATTERN_DATE_TIME));
        map.put("8", DateUtil.timeStamp2Date(Long.parseLong(timestamp), DateUtil.PATTERN_DATE_TIME));
        map.put("9", ips);
        map.put("10", types);
        map.put("11", levels);
        map.put("12", nums);
        map.put("13", relationSup);
        map.put("sql", sql);
        return map;
    }

    private static Map<String, String> getUpdateEventGroupSql(String eventGroupId, String relationEle, String relationSup, String timestamp, String ips, String types, String levels, String nums) {
        Map<String, String> map = new HashMap<>();
        String sql = "UPDATE event_group SET relation_ele = ?, update_time = ?, end_time = ?, types = ?, levels = ?, nums = ?, ips = ?, relation_sup = ? WHERE event_group_id = ?";
        map.put("1", relationEle);
        map.put("2", DateUtil.format(new Date(), DateUtil.PATTERN_DATE_TIME));
        map.put("3", DateUtil.timeStamp2Date(Long.parseLong(timestamp), DateUtil.PATTERN_DATE_TIME));
        map.put("4", types);
        map.put("5", levels);
        map.put("6", nums);
        map.put("7", ips);
        map.put("8", relationSup);
        map.put("9", eventGroupId);
        map.put("sql", sql);
        return map;
    }


    /*private static PreparedStatement getInsertEventGroupEventSql(Connection conn,Map<String, Object> map,String eventGroupId) throws Exception{
        PreparedStatement preparedStatement = conn.prepareStatement("INSERT INTO event_group_event (event_id, type, event_group_id, uuid, create_time, event_time, point_id, process_status, level, ip, arguments) VALUES ( ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?)");
        preparedStatement.setString(1,map.getOrDefault("id","").toString());
        preparedStatement.setString(2,map.getOrDefault("log_name","").toString());
        preparedStatement.setString(3,eventGroupId);
        preparedStatement.setString(4,map.getOrDefault("uuid","").toString());
        preparedStatement.setString(5,DateUtil.format(new Date(),DateUtil.PATTERN_DATE_TIME));
        preparedStatement.setString(6,DateUtil.timeStamp2Date(Long.parseLong(new BigDecimal(map.get("timestamp").toString()).toPlainString()),DateUtil.PATTERN_DATE_TIME));
        // todo 溯源图关系
        preparedStatement.setInt(7,1);
        preparedStatement.setInt(8,0);
        preparedStatement.setInt(9,(int)Double.parseDouble(map.get("level").toString()));
        preparedStatement.setString(10,map.getOrDefault("ip_address","").toString());
        preparedStatement.setString(11,JSON.toJSONString(map.get("arguments")));
        return preparedStatement;
    }*/


}

class ConnectionPool {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionPool.class);
    private String jdbcDriver = ""; // 数据库驱动
    private String dbUrl = ""; // 数据 URL
    private String dbUsername = ""; // 数据库用户名
    private String dbPassword = ""; // 数据库用户密码
    private String testTable = "policy"; // 测试连接是否可用的测试表名，默认没有测试表
    private int initialConnections = 10; // 连接池的初始大小
    private int incrementalConnections = 5;// 连接池自动增加的大小
    private int maxConnections = 50; // 连接池最大的大小
    private Vector connections = null; // 存放连接池中数据库连接的向量 , 初始时为 null

    public ConnectionPool(String jdbcDriver, String dbUrl, String dbUsername, String dbPassword) {
        logger.info("jdbcDriver: {}", jdbcDriver);
        logger.info("dbUrl: {}", dbUrl);
        logger.info("dbUsername: {}", dbUsername);
        logger.info("dbPassword: {}", dbPassword);
        this.jdbcDriver = jdbcDriver;
        this.dbUrl = dbUrl;
        this.dbUsername = dbUsername;
        this.dbPassword = dbPassword;
        try {
            createPool();
        } catch (Exception e) {
            logger.error(" 数据库连接池创建失败！", e);
            try {
                Thread.sleep(1000 * 60);
            } catch (InterruptedException interruptedException) {
                interruptedException.printStackTrace();
            }
        }
    }

    /**
     * 创建一个数据库连接池，连接池中的可用连接的数量采用类成员
     * initialConnections 中设置的值
     */

    public synchronized void createPool() throws Exception {
        if (connections != null) {
            return;
        }
        Driver driver = (Driver) (Class.forName(this.jdbcDriver).newInstance());
        DriverManager.registerDriver(driver);
        connections = new Vector();
        createConnections(this.initialConnections);
        logger.info(" 数据库连接池创建成功！ {}");
    }

    @SuppressWarnings("unchecked")
    private void createConnections(int numConnections) throws SQLException {
        for (int x = 0; x < numConnections; x++) {
            if (this.maxConnections > 0 && this.connections.size() >= this.maxConnections) {
                break;
            }
            try {
                connections.addElement(new PooledConnection(newConnection()));
            } catch (CommunicationsException e) {
                logger.error(" 数据库连接失败！", e);
                throw e;
            } catch (SQLException e) {
                logger.error(" 数据库连接池创建失败！ {}", e);
                throw e;
            }
        }
    }

    private Connection newConnection() throws SQLException {
        Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
        if (connections.size() == 0) {
            DatabaseMetaData metaData = conn.getMetaData();
            int driverMaxConnections = metaData.getMaxConnections();
            if (driverMaxConnections > 0 && this.maxConnections > driverMaxConnections) {
                this.maxConnections = driverMaxConnections;
            }
        }
        return conn;
    }

    public synchronized Connection getConnection() throws SQLException {
        if (connections == null) {
            return null;
        }
        Connection conn = getFreeConnection();
        int count = 0;
        while (conn == null && count < 5) {
            count++;
            wait(250);
            conn = getFreeConnection();
        }
        return conn;
    }


    private void wait(int mSeconds) {
        try {
            Thread.sleep(mSeconds);
        } catch (InterruptedException e) {
        }
    }


    private Connection getFreeConnection() throws SQLException {
        Connection conn = findFreeConnection();
        if (conn == null) {
            createConnections(incrementalConnections);
            conn = findFreeConnection();
            if (conn == null) {
                return null;
            }
        }
        return conn;
    }

    private Connection findFreeConnection() throws SQLException {
        Connection conn = null;
        PooledConnection pConn = null;
        Enumeration enumerate = connections.elements();
        while (enumerate.hasMoreElements()) {
            pConn = (PooledConnection) enumerate.nextElement();
            if (!pConn.isBusy()) {
                conn = pConn.getConnection();
                pConn.setBusy(true);
                if (!testConnection(conn)) {
                    try {
                        conn = newConnection();
                    } catch (SQLException e) {
                        logger.error(" 数据库连接池创建失败！ {}", e);
                        return null;
                    }
                    pConn.setConnection(conn);
                }
                break;
            }
        }
        return conn;
    }

    private boolean testConnection(Connection conn) throws SQLException {
        Statement stmt = null;
        try {
            if (testTable.equals("")) {
                conn.setAutoCommit(true);
            } else {
                stmt = conn.createStatement();
                stmt.execute("select count(*) from " + testTable);
            }
        } catch (SQLException e) {
            closeConnection(conn);
            return false;
        }finally {
            if(stmt !=null){
                stmt.close();
            }
        }
        return true;
    }

    public void returnConnection(Connection conn) {
        if (connections == null) {
            logger.info(" 连接池不存在，无法返回此连接到连接池中 !");
            return;
        }
        PooledConnection pConn = null;
        Enumeration enumerate = connections.elements();
        while (enumerate.hasMoreElements()) {
            pConn = (PooledConnection) enumerate.nextElement();
            if (conn == pConn.getConnection()) {
                pConn.setBusy(false);
                break;
            }
        }
    }


    private void closeConnection(Connection conn) {
        try {
            conn.close();
        } catch (SQLException e) {
            logger.error(" 关闭数据库连接出错： {}", e);
        }
    }

    class PooledConnection {
        Connection connection = null;
        boolean busy = false;

        public PooledConnection(Connection connection) {
            this.connection = connection;
        }

        public Connection getConnection() {
            return connection;
        }

        public void setConnection(Connection connection) {
            this.connection = connection;
        }

        public boolean isBusy() {
            return busy;
        }

        public void setBusy(boolean busy) {
            this.busy = busy;
        }
    }

}

class DateUtil extends org.apache.commons.lang3.time.DateUtils {

    public static final String PATTERN_DATE_TIME = "yyyy-MM-dd HH:mm:ss";

    public static String format(Date date, String pattern) {
        if (date == null) {
            return null;
        }
        return DateFormatUtils.format(date, pattern);
    }

    public static String timeStamp2Date(Long timeStamp, String format) {
        if (timeStamp == null) {
            return "";
        }
        if (format == null || format.isEmpty()) {
            format = PATTERN_DATE_TIME;
        }

        if (String.valueOf(timeStamp).length() == 19) { // 纳秒
            timeStamp = Long.valueOf(String.valueOf(timeStamp).substring(0, String.valueOf(timeStamp).length() - 6));
        }
        if (String.valueOf(timeStamp).length() == 16) { // 微秒
            timeStamp = Long.valueOf(String.valueOf(timeStamp).substring(0, String.valueOf(timeStamp).length() - 3));
        }
        if (String.valueOf(timeStamp).length() == 13) { // 毫秒
        }
        if (String.valueOf(timeStamp).length() == 10) { // 秒
            timeStamp = Long.valueOf(timeStamp + "000");
        }
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        return sdf.format(new Date(Long.parseLong(String.valueOf(timeStamp))));
    }
}