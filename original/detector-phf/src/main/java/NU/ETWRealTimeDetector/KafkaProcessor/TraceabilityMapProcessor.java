package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.core.CountRequest;
import org.elasticsearch.client.core.CountResponse;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.SortOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.*;

import java.util.Date;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;


public class TraceabilityMapProcessor {

    private static final Logger logger = LoggerFactory.getLogger("old_event_group");

    private static LinkedBlockingQueue<Map<String, String>> linkedBlockingQueue = new LinkedBlockingQueue<>();

    private static final String elasticSearch = SysConfig.getString("ElasticSearch", "127.0.0.1:9200");
    private static final String username = SysConfig.getString("ESUserName");
    private static final String password = SysConfig.getString("ESPassword");


    private static RestHighLevelClient client = null;
    private static Connection conn = null;


    private static Connection getConnection() throws Exception {
        String driveName = "com.mysql.jdbc.Driver";
        String url = "jdbc:mysql://127.0.0.1:3306/cornerstone";
        String user = "root";
        String pass = "Magic123456#$%";
        Class.forName(driveName);
        return DriverManager.getConnection(url, user, pass);
    }

    public static void delRedisOldData() {
        Jedis jedis = JedisPoolUtil.getJedis();
        Set<String> keys = jedis.keys("event_group*");
        if (keys.size() > 0) {
            jedis.del(keys.toArray(new String[0]));
        }
        jedis.close();
    }

    private static RestHighLevelClient restHighLevelClient() {
        String[] arr = elasticSearch.split(":");
        String host = arr[0];
        int port = Integer.parseInt(arr[1]);
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        RestClientBuilder builder = RestClient.builder(new HttpHost(host, port, "http"));
        builder.setRequestConfigCallback(requestConfigBuilder -> {
            requestConfigBuilder.setConnectTimeout(5000000);
            requestConfigBuilder.setSocketTimeout(5000000);
            requestConfigBuilder.setConnectionRequestTimeout(5000000);
            return requestConfigBuilder;
        });
        // 异步连接数配置
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            httpClientBuilder.setMaxConnTotal(100);
            httpClientBuilder.setMaxConnPerRoute(100);
            return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        });
        return new RestHighLevelClient(builder);
    }

    public static void processOldData() {
        try {
            client = restHighLevelClient();
            delRedisOldData();
            conn = getConnection();
            Statement statement = conn.createStatement();
            ResultSet rs = statement.executeQuery("select count(*) as count from event_group");
            if (rs.next()) {
                long count = rs.getLong("count");
                if (count > 0) {
                    long size = 500;
                    long page = 1;
                    if (count > size) {
                        page = count / size;
                        if (count % size != 0) {
                            page += 1;
                        }
                    }
                    for (long i = 0; i < page; i++) {
                        String sql = String.format("select * from event_group limit %s,%s", i * size, size);
                        rs = statement.executeQuery(sql);
                        while (rs.next()) {
                            String eventGroupId = rs.getString("event_group_id");
                            processEventGroup(eventGroupId);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (client != null) {
                try {
                    client.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static void processEventGroup(String eventGroupId) {
        try {
            CountRequest request = new CountRequest("event");
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
            boolQuery.must(QueryBuilders.matchQuery("event_group_id", eventGroupId));
            request.query(boolQuery);
            CountResponse response = client.count(request, RequestOptions.DEFAULT);
            long count = response.getCount();
            if (count > 0) {
                int size = 5000;
                long page = 1;
                if (count > size) {
                    page = count / size;
                    if (count % size != 0) {
                        page += 1;
                    }
                }
                for (long i = 0; i < page; i++) {
                    processEvent(eventGroupId, i, size);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processEvent(String eventGroupId, long page, int size) {
        try {
            SearchRequest request = new SearchRequest("event");
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder().trackTotalHits(true).timeout(new TimeValue(120, TimeUnit.SECONDS));
            sourceBuilder.from((int) page * size);
            sourceBuilder.size(size);
            sourceBuilder.sort("timestamp", SortOrder.ASC);
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
            boolQuery.must(QueryBuilders.matchQuery("event_group_id", eventGroupId));
            sourceBuilder.query(boolQuery);
            request.source(sourceBuilder);
            SearchResponse response = client.search(request, RequestOptions.DEFAULT);
            SearchHits hits = response.getHits();
            Map<String, String> logs = new HashMap<>();
            for (SearchHit hit : hits) {
                Map<String, Object> logMap = hit.getSourceAsMap();
                String logId = hit.getId();
                String logJson = process(logMap);
                logs.put(logId, logJson);
                updateSQL();
            }
            batchUpdateEs(logs);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private static void batchUpdateEs(Map<String, String> logs) {
        try {
            BulkRequest request = new BulkRequest("event");
            for (String logId : logs.keySet()) {
                String logJson = logs.get(logId);
                UpdateRequest update = new UpdateRequest();
                update.id(logId);
                update.doc(logJson, XContentType.JSON);
                request.add(update);
            }
            BulkResponse response = client.bulk(request, RequestOptions.DEFAULT);
            if (response.hasFailures()) {
                logger.error("event update fail");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void updateSQL() {
        try {
            Map<String, String> map = linkedBlockingQueue.poll();
            PreparedStatement ps = conn.prepareStatement(map.get("sql"));
            for (String key : map.keySet()) {
                if ("sql".equals(key)) {
                    continue;
                }
                // 12个参数是保存sql，其他是更新sql
                if (map.size() > 11) {
                    if ("3".equals(key) || "12".equals(key)) {
                        ps.setInt(Integer.parseInt(key), Integer.parseInt(map.get(key)));
                    } else {
                        ps.setString(Integer.parseInt(key), map.get(key));
                    }
                } else {
                    if ("6".equals(key)) {
                        ps.setInt(Integer.parseInt(key), Integer.parseInt(map.get(key)));
                    } else {
                        ps.setString(Integer.parseInt(key), map.get(key));
                    }
                }
            }
            ps.executeUpdate();
            ps.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String process(Map<String, Object> map) {
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
            String eventGroupId = (String) map.get("event_group_id");
            String traceabilityMap = "";

            // 上级节点事件id
            String superior = "";
            // 关联字段
            String superiorField = "";
            // 关联字段值
            String superiorFieldValue = "";

            String globalLocalIpRedisKey = "event_group:local_ip";// 缓存受害者ip对应的事件组

            Map<String, String> tmp = new HashMap<>();

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

            String relationField = String.format("%s:%s", superiorField, superiorFieldValue);

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
                traceabilityMap = "1";
                eventDistinct(jedis, logName, ipAddress, relationField, eventGroupDistinctRedisKey, eventId);
                addLocalIpToRelation(jedis, ipAddress, eventGroupId, remoteIp, tmp, eventId, globalLocalIpRedisKey, eventGroupLocalIpRedisKey);
                insertEventGroup(jedis, tmp, eventGroupRedisKey);
                linkedBlockingQueue.add(getUpdateEventGroupSql(eventGroupId, JSON.toJSONString(tmp), timestamp, ips, types, levels, nums));
            } else {
                // 事件组存在，更新相关信息
                Map<String, String> eventGroupRelationFiled = jedis.hgetAll(String.format("event_group:%s", eventGroupId));
                if ("remote_ip".equals(superiorField)) {
                    if (2 == exist) {
                        // 受害者ip作为远端ip关联进来时，起点为更新该ip的事件
                        superior = jedis.hget(eventGroupLocalIpRedisKey, superiorFieldValue);
                    }
                } else if (!"domain".equals(superiorField)) {
                    superior = jedis.hget(eventGroupSuperiorRedisKey, superiorField);
                }

                // 去重
                String repeatEventId = eventDistinct(jedis, logName, ipAddress, relationField, eventGroupDistinctRedisKey, eventId);
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
                addLocalIpToRelation(jedis, ipAddress, eventGroupId, remoteIp, eventGroupRelationFiled, eventId, globalLocalIpRedisKey, eventGroupLocalIpRedisKey);
                linkedBlockingQueue.add(getUpdateEventGroupSql(eventGroupId, JSON.toJSONString(eventGroupRelationFiled), timestamp, ips, types, levels, nums));
            }

            map.put("traceability_map", traceabilityMap);
            map.put("event_group_id", eventGroupId);
            map.put("superior", superior);
            map.put("relation_field", relationField);
            return JSONObject.toJSONString(map);
        } catch (Exception e) {
            logger.error("事件组数据处理错误 {}", e);
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
     *
     * @return event_id 返回已存在的事件id
     */
    private static String eventDistinct(Jedis jedis, String logName, String ipAddress, String relationField, String eventGroupDistinctRedisKey, String eventId) {
        // 普通节点
        String commonNode = logName + ipAddress + relationField;
        // 起始节点
        String startNode = logName + ipAddress + ":";
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

    private static Map<String, String> getInsertEventGroupSql(String eventGroupId, String relationEle, String timestamp, String ips, String types, String levels, String nums) {
        Map<String, String> map = new HashMap<>();
        String sql = "INSERT INTO event_group (event_group_id,relation_ele,process_status, description, create_time, update_time, start_time, end_time, ips, types, levels, nums) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
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
        map.put("sql", sql);
        return map;
    }

    private static Map<String, String> getUpdateEventGroupSql(String eventGroupId, String relationEle, String timestamp, String types, String levels, String nums) {
        Map<String, String> map = new HashMap<>();
        String sql = "UPDATE event_group SET relation_ele = ?,update_time = ?,end_time = ?,types = ?,levels = ?,nums=? WHERE event_group_id = ?";
        map.put("1", relationEle);
        map.put("2", DateUtil.format(new Date(), DateUtil.PATTERN_DATE_TIME));
        map.put("3", DateUtil.timeStamp2Date(Long.parseLong(timestamp), DateUtil.PATTERN_DATE_TIME));
        map.put("4", types);
        map.put("5", levels);
        map.put("6", nums);
        map.put("7", eventGroupId);
        map.put("sql", sql);
        return map;
    }

    private static Map<String, String> getUpdateEventGroupSql(String eventGroupId, String relationEle, String timestamp, String ips, String types, String levels, String nums) {
        Map<String, String> map = new HashMap<>();
        String sql = "UPDATE event_group SET relation_ele = ?,update_time = ?,end_time = ?,types = ?,levels = ?,nums = ?,ips = ? WHERE event_group_id = ?";
        map.put("1", relationEle);
        map.put("2", DateUtil.format(new Date(), DateUtil.PATTERN_DATE_TIME));
        map.put("3", DateUtil.timeStamp2Date(Long.parseLong(timestamp), DateUtil.PATTERN_DATE_TIME));
        map.put("4", types);
        map.put("5", levels);
        map.put("6", nums);
        map.put("7", ips);
        map.put("8", eventGroupId);
        map.put("sql", sql);
        return map;
    }
}