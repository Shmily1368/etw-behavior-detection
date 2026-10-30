package NU.ETWRealTimeDetector.EventRule;

import NU.ETWRealTimeDetector.EventRule.pojo.Rule;
import NU.ETWRealTimeDetector.EventRule.pojo.RuleCacheDict;
import NU.ETWRealTimeDetector.EventRule.rule.*;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.params.SetParams;

import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class CheckRule {

    private static final String centerUrl = SysConfig.getString("CenterUrl", "http://127.0.0.1:8899");

    private static final Logger logger = LoggerFactory.getLogger("CheckRule");
    private static Gson gson = new Gson();

    private static List<Rule> rules = new CopyOnWriteArrayList<Rule>();
    private static long ruleTime = 0L;
    //    public static void main(String[] args) {
//        Jedis db = JedisPoolUtil.getJedis();
//        String str = db.get("eventRule");
////        transformRule(str);
//        Gson gson = new Gson();
//        HttpRequest httpRequest = HttpRequest.get("http://127.0.0.1:8899/api/event/rule/all");
//        String body = httpRequest.body();
//        HashMap response = gson.fromJson(body, HashMap.class);
//        double code = Double.parseDouble(response.get("code").toString());
//        if (code != 0) {
//            return;
//        }
//        String data = response.get("data").toString();
//        Type type = new TypeToken<List<Rule>>() {}.getType();
//        List<Rule> rules = gson.fromJson(data, type);
//        System.out.println(rules);
//    }
//    public static void run(List<Rule> rules, HashMap<String, Object> log) {
//        RuleCacheDict dict = check(log, rules);
//        if (dict != null) {
//            HashMap<String, Object> event = new HashMap<>();
//            event.put("log_name", dict.getMeta().getId());
//            event.put("log_category", "EventRule");
//            event.put("event_category", "EventRule");
//            event.put("event", true);
//            event.put("level", dict.getMeta().getLevel());
//            event.put("behavior", 1);
//            event.put("operating", "");
//            event.put("terminate", 1);
//            event.put("result", 0);
//
//            HashMap<String, Object> arguments = new HashMap<>();
//            arguments.put("all_log_ids", dict.getAllLogIds());
//            event.put("arguments", arguments);
//        }
//    }
    private static ObjectMapper objectMapper = new ObjectMapper();

    public static  RuleCacheDict check(Map<String, Object> log) {
        updateRule();
        if (rules == null || rules.isEmpty()) {
            return null;
        }
        for (Rule rule : rules) {
            if (rule.getEnable() == 0) {
                continue;
            }
            Integer templateType = rule.getTemplateType();
            BaseRule ruleEngine = null;
            switch (templateType) {
                case 1:
                    ruleEngine = new GeneralRule(rule, log);
                    break;
                case 2:
                    ruleEngine = new GeneralCountRule(rule, log);
                    break;
                case 3:
                    ruleEngine = new UnionRule(rule, log);
                    break;
                case 4:
                    ruleEngine = new ThresholdRule(rule, log);
                    break;
                default:
                    return null;
            }
            Boolean result = ruleEngine.validate();
            if (!result) {
                continue;
            }

            RuleCacheDict alarm = ruleEngine.process();
            if (alarm != null && alarm.isNext()) {
                continue;
            }
            return alarm;
        }
        return null;
    }

    public static String createEvent(RuleCacheDict dict) {
        Map<String, Object> log = dict.getAllLogs().size() > 0 ? dict.getAllLogs().get(0) : dict.getLogs().get(0);
        HashMap<String, Object> event = new HashMap<>();
        event.put("id", UUID.randomUUID().toString());
        event.put("log_name", dict.getMeta().getId());
        event.put("log_category", "EventRule");
        event.put("event_category", "EventRule");
        event.put("event", true);
        event.put("level", dict.getMeta().getLevel());
        event.put("behavior", dict.getMeta().getBehavior());
        event.put("operating", "");
        event.put("terminate", 1);
        event.put("result", 0);

        event.put("host_name", log.getOrDefault("hostname", ""));
        event.put("ip_address", log.getOrDefault("ip_address", ""));
        event.put("ipv6_address", log.getOrDefault("ipv6_address", ""));
        event.put("mac", log.getOrDefault("mac", ""));
        event.put("uuid", log.getOrDefault("uuid", ""));
        event.put("os_type", log.getOrDefault("os_type", ""));
        event.put("os_version", log.getOrDefault("version", "")); //
        event.put("timestamp", System.currentTimeMillis());
        event.put("policy_id", "");
        event.put("source", "EventRule");
        event.put("operation_mode", dict.isStudy() ? 2 : 0);
        event.put("attck_tactics", "");
        event.put("attck_techniques", "");

        HashMap<String, Object> arguments = new HashMap<>();

        String allLogIds = dict.getAllLogIds().stream().filter(s -> !s.isEmpty()).collect(Collectors.joining(","));
        arguments.put("all_log_ids", allLogIds);
        arguments.put("rule_name", dict.getMeta().getName());
        arguments.put("rule_description", dict.getMeta().getDescription());
        arguments.put("rule_solution", dict.getMeta().getSolution());

        event.put("arguments", arguments);
        //Gson gson = new Gson();
        //return gson.toJson(event);
        try {
            String json = objectMapper.writeValueAsString(event);
            logger.info("{}", json);
            return json;
        } catch (JsonProcessingException e) {
            logger.error("json serialize error", e);
        }
        return null;
    }

    private static void updateRule() {
        long current = System.currentTimeMillis();
        if (current - ruleTime < 60000) {
            return;
        }
        ruleTime = current;
        Type type = new TypeToken<List<Rule>>() {
        }.getType();
        Gson gson = new Gson();
        try (Jedis db = JedisPoolUtil.getJedis()) {
            String eventRuleStr = db.get("eventRule");
            List<Rule> ruleList;

            if (StringUtils.isEmpty(eventRuleStr)) {
                ruleList = getEventRuleFromCenter();
                logger.info("update rule from center");
                rules.clear(); // 不管有没有从管控拉取到规则，都要把内存清空，防止管控数据为空时，内存里的规则无法失效
                if (ruleList != null && !ruleList.isEmpty()) {
                    rules.addAll(ruleList);
                }
                return;
            }

            ruleList = gson.fromJson(eventRuleStr, type);
            logger.info("update rule from redis");
            if (ruleList != null && !ruleList.isEmpty()) {
                rules.clear();
                rules.addAll(ruleList);
            }
        } catch (Exception e) {
            logger.error("update rule error", e);
        }
    }

    private static List<Rule> getEventRuleFromCenter() {
        HttpRequest httpRequest = HttpRequest.get(centerUrl + "/api/event/rule/all");
        String body = httpRequest.body();
        HashMap response = gson.fromJson(body, HashMap.class);
        double code = Double.parseDouble(response.getOrDefault("code", -1).toString());
        if (code != 0) {
            return null;
        }

        String data = response.getOrDefault("data", "").toString();
        if (StringUtils.isEmpty(data)) {
            return null;
        }

        // 存入redis
        try (Jedis db = JedisPoolUtil.getJedis()) {
            db.set("eventRule", data, SetParams.setParams().ex(60L));
        }

        List<Rule> list = new ArrayList<>();
        Type type = new TypeToken<List<Rule>>() {
        }.getType();

        try {
            list.addAll(gson.fromJson(data, type));
        } catch (Exception e) {
            logger.error("get event rule from center error", e);
        }
        return list;
    }
}
