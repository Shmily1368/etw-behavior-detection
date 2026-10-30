package NU.ETWRealTimeDetector.EventRule.rule;

import NU.ETWRealTimeDetector.EventRule.engine.Condition;
import NU.ETWRealTimeDetector.EventRule.engine.Engine;
import NU.ETWRealTimeDetector.EventRule.pojo.*;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.params.SetParams;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Arrays.asList;

public abstract class BaseRule {
    private static final Logger logger = LoggerFactory.getLogger("BaseRule");

    final String CACHE_KEY_PREFIX = "cep:%s";
    Map<String, Object> log;
    public final String logIdField = "id";
    Rule rule;
    String ruleId;
    RuleContent ruleData;
    RuleCacheDict ruleCacheDict;
    // 缓存分值
    Integer score = 0;

    public BaseRule(Rule rule, Map<String, Object> log) {
        this.log = log;
        this.rule = rule;
        this.ruleId = rule.getId();
        this.ruleData = rule.getRule();

        MetaRule metaRule = new MetaRule();
        metaRule.setId(rule.getId());
        metaRule.setName(rule.getName());
        metaRule.setDescription(rule.getDescription());
        metaRule.setSolution(rule.getSolution());
        metaRule.setTemplateType(rule.getTemplateType());
        metaRule.setEventId(rule.getEventId());
        metaRule.setLevel(rule.getLevel());
        metaRule.setBehavior(rule.getBehavior());
        metaRule.setCount(rule.getRule().getCount());
        metaRule.setGroupFields(rule.getRule().getGroupFields());
        metaRule.setTimeWindow(rule.getRule().getTimeWindow());
        metaRule.setAssociation(rule.getRule().getAssociation());
        metaRule.setEvents(rule.getRule().getEvents());
        metaRule.setEventCount(rule.getRule().getEvents().size());

//        this.meta = metaRule;
//
//        this.logs = new ArrayList<>();
//        this.allLogs = new ArrayList<>();
//        this.allLogIds = new ArrayList<>();
//        this.eventNames = new ArrayList<>();
//        this.count = 0;
        this.ruleCacheDict = new RuleCacheDict();
        this.ruleCacheDict.setMeta(metaRule);
        int operationMode = (Integer) log.getOrDefault("operation_mode",0);
        checkStudy(operationMode);

    }

    public Boolean validate() {
        Condition condition = transformRuleData(log, ruleData);
        Engine engine = new Engine(condition);
        if (!engine.isValid) {
            return false;
        }
        boolean flag = engine.evaluate();
        if (flag) {
            // 把分值放入
            this.score = engine.score;
        }
        return flag;
    }

    public Condition transformRuleData(Map<String, Object> log, RuleContent ruleData) {
        Condition condition = new Condition();
        condition.setOperator("and");
        for (Event event : ruleData.getEvents()) {
            Condition c = transformEventCondition(log, event, false);
            condition.getArgs().add(c);
        }
        return condition;
    }

    public Condition transformEventCondition(Map<String, Object> log, Event event, boolean isAssociation) {
        String operator = event.getOperator().toLowerCase();
        List<Filter> filterList = event.getFilter() == null ? new ArrayList<>() : event.getFilter();
        Condition condition = new Condition();
        condition.setOperator(operator);

        for (Filter filter : filterList) {
            String op = filter.getMiddle();
            // todo get value from log
            // TODO 对值是否需要转小写
            // TODO 时间戳double
            String source = getFromDict(log, filter.getLeft());
            String target;

            // 关联条件target取的是log里对应的值，事件条件target直接取的是条件filter里的right值
            if (isAssociation) {
                target = getFromDict(log, filter.getRight());
            } else {
                target = filter.getRight();
            }

            Condition c = new Condition(op, asList(source, target), filter.getScore());
            condition.getArgs().add(c);
        }
        return condition;
    }

    public abstract RuleCacheDict process();

    public String getFromDict(Map<String, Object> log, String field) {
        return fieldCheck(getItem(log, field));
    }

    private String getItem(Map<String, Object> map, String field) {
        String[] arr = field.split("\\.");
        Map<String, Object> newMap = new HashMap<>(map);
        for (int i = 0; i < arr.length; i++) {
            Object obj = newMap.getOrDefault(arr[i], "");
            if (!(obj instanceof Map)) {
                return obj.toString();
            }
            newMap = (Map<String, Object>) obj;
        }

        return "";
    }


    private String fieldCheck(String field) {
        // 处理“0.0”的double数据
        if (Pattern.matches("\\d+\\.0$", field)) {
            return field.substring(0, field.length() - 2);
        }
        return field;
    }

    private void checkStudy(Integer operationMode) {
        if (operationMode == 2) this.ruleCacheDict.setStudy(true);
    }

    public String getCacheKey() {
        return String.format(CACHE_KEY_PREFIX, this.ruleId);
    }

    public Object[] getCacheData(String cacheKey, RuleCacheDict ruleCacheDict) {
        if (ruleCacheDict == null) {
            ruleCacheDict = new RuleCacheDict();
        }
        boolean isExists = false;

        String ruleCacheContent = "";
        try (Jedis db = JedisPoolUtil.getJedis()) {
            ruleCacheContent = db.get(cacheKey);
        } catch (Exception e) {
            logger.error("get cache from redis error", e);
        }

        RuleCacheDict ruleCacheData = new RuleCacheDict();
        if (StringUtils.isNotEmpty(ruleCacheContent)) {
            isExists = true;
            JSONObject jsonObject = JSON.parseObject(ruleCacheContent);
            ruleCacheData = JSONObject.toJavaObject(jsonObject, RuleCacheDict.class);
        } else {
            BeanUtils.copyProperties(ruleCacheDict, ruleCacheData);
        }
        // 继承学习模式的状态
        if (ruleCacheDict.isStudy()) {
            ruleCacheData.setStudy(true);
        }
        return new Object[]{isExists, ruleCacheData};
    }

    public void setCache(String cacheKey, RuleCacheDict ruleCacheDict, Long expireTime, boolean isExists) {
        try (Jedis db = JedisPoolUtil.getJedis()) {
            if (isExists) {
                expireTime = db.ttl(cacheKey);
            }
            String cacheContent = JSONArray.toJSON(ruleCacheDict).toString();

            // 机率性会遇到expire_time = -1
            if (expireTime < 1) {
                return;
            }
            db.set(cacheKey, cacheContent, SetParams.setParams().ex(expireTime));
        } catch (Exception e) {
            logger.error("set cache error", e);
        }
    }

    public void delCache(String cacheKey) {
        try (Jedis db = JedisPoolUtil.getJedis()) {
            db.del(cacheKey);
        } catch (Exception e) {
            logger.error("del key error", e);
        }
    }

    public Long getTimeWindowInterval(TimeWindow template) {
        Long Interval = template.getInterval();
        String unit = template.getUnit();
        Integer seconds = 1;
        switch (unit) {
            case "second":
                seconds = 1;
                break;
            case "minute":
                seconds = 60;
                break;
            case "hour":
                seconds = 60 * 60;
                break;
            case "day":
                seconds = 60 * 60 * 24;
                break;
        }

        return Interval * seconds;
    }

    public void appendLog(RuleCacheDict ruleCacheData, HashMap<String, Object> cacheLog, String logId) {
        ruleCacheData.getLogs().add(cacheLog);
        ruleCacheData.getAllLogIds().add(logId);
//        String eventAliasName = cacheLog.getOrDefault("alias_name", "").toString();
//        if (!eventAliasName.isEmpty() && !ruleCacheData.getEventNames().contains(eventAliasName)) {
//            ruleCacheData.getEventNames().add(eventAliasName);
//        }
    }

    public void appendEventAliasName(String eventName, RuleCacheDict ruleCacheData) {
        List<List<String>> eventNameCaches = ruleCacheData.getEventNameCaches();
        for (List<String> eventNameList : eventNameCaches) {
            // 如果不存在，则添加
            if (!eventNameList.contains(eventName)) {
                eventNameList.add(eventName);
                break;
            }
        }
    }

    public boolean appendEventLog(RuleCacheDict ruleCacheData, HashMap<String, Object> cacheLog, String eventName) {
        List<Map<String, Object>> eventLogCaches = ruleCacheData.getEventLogCaches();
        for (Map<String, Object> map : eventLogCaches) {
            if (map.get(eventName) == null) {
                map.put(eventName, cacheLog);
                return true;
            }
        }
        return false;
    }

}
