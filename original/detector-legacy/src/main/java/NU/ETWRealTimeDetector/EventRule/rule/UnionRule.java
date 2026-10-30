package NU.ETWRealTimeDetector.EventRule.rule;

import NU.ETWRealTimeDetector.EventRule.engine.Condition;
import NU.ETWRealTimeDetector.EventRule.engine.Engine;
import NU.ETWRealTimeDetector.EventRule.pojo.*;
import NU.ETWRealTimeDetector.Util.JedisPoolUtil;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import com.alibaba.fastjson.JSON;
import redis.clients.jedis.Jedis;

import java.util.*;

public class UnionRule extends BaseRule {
    private static final Logger logger = LoggerFactory.getLogger("event_rule");

    String LOG_SOURCE_GUID_FIELD = "uuid";

    public UnionRule(Rule rule, Map<String, Object> log) {
        super(rule, log);
    }

    @Override
    public Boolean validate() {
        return true;
    }

    @Override
    public RuleCacheDict process() {
        List<Event> events = this.ruleData.getEvents();
        TimeWindow timeWindow = this.ruleData.getTimeWindow();
//        TimeWindowTemplate trigger = timeWindow.getTrigger();
        Long expireTime = this.getTimeWindowInterval(timeWindow);

        int count = this.ruleCacheDict.getMeta().getCount();
        String defaultCacheKey = this.getCacheKey();

        for (int index = 0; index < events.size(); index++) {
            Event event = events.get(index);
            Condition condition = this.transformEventCondition(this.log, event, false);
            Engine engine = new Engine(condition);
            if (!engine.evaluate()) {
                // 当前规则下未匹配任何一个条件组，则让它继续取匹配下一个规则
                if (index == events.size() - 1) {
                    RuleCacheDict data = new RuleCacheDict();
                    data.setNext(true);
                    return data;
                }

                continue;
            }
            // cep:rule_id:template_type:uuid

            String eventAliasName = event.getAliasName();
            HashMap<String, Object> cacheLog = new HashMap<>(this.log);
            cacheLog.put("alias_name", eventAliasName);
            String logId = cacheLog.get(this.logIdField).toString();
            String hashKeyValue = this.log.get(this.LOG_SOURCE_GUID_FIELD).toString();
            String hashKey = DigestUtils.md5Hex(hashKeyValue);
            String cacheKey = String.format("%s:%s:%s", defaultCacheKey, this.rule.getTemplateType(), hashKey);// cep:17:3:b93050dd191531db78516205e0c99a53

            if (index == 0) {
                // 第一个条件关联已经命中过的同一来源主机过滤掉
                Object[] rst = this.getCacheData(cacheKey, this.ruleCacheDict);

                boolean isExists = (boolean) rst[0];
                RuleCacheDict ruleCacheData = (RuleCacheDict) rst[1];

                // 同一条日志的这种关联匹配到就没必要了，直接跳过
                if (ruleCacheData.getAllLogIds().contains(logId)) {
                    return null;
                }

                // 定义好数据长度
                if (!isExists) {
                    ruleCacheData.setEventNameCaches(new ArrayList<List<String>>(count){{
                        for (int i = 0; i < count;i++) {
                            add(new ArrayList<>());
                        }
                    }});
                    ruleCacheData.setEventLogCaches(new ArrayList<Map<String, Object>>(count){{
                        for (int i = 0; i < count;i++) {
                            add(new HashMap<>());
                        }
                    }});
                }

                this.appendEventAliasName(eventAliasName, ruleCacheData);
                if (this.appendEventLog(ruleCacheData, cacheLog, eventAliasName)) {
                    this.appendLog(ruleCacheData, cacheLog, logId);// 过滤超出匹配次数的日志
                }

//                if (!isExists) {
//                    try (Jedis db = JedisPoolUtil.getJedis()) {
//                        db.sadd(ruleCacheListKey, cacheKey);
//                    } catch (Exception e) {
//                        logger.error("add to redis error", e);
//                    }
//                }

                this.setCache(cacheKey, ruleCacheData, expireTime, isExists);
                return null;

            } else {
                try (Jedis db = JedisPoolUtil.getJedis()) {
                    String ruleCacheContent = db.get(cacheKey);
                    if (ruleCacheContent == null) {
                        RuleCacheDict data = new RuleCacheDict();
                        data.setNext(true);
                        return data;
                    }

                    RuleCacheDict ruleCacheData = JSON.parseObject(ruleCacheContent, RuleCacheDict.class);

                    int idx = 0;
                    boolean flag = false;
                    for (int i = 0; i < ruleCacheData.getEventNameCaches().size(); i++) {
                        if (!ruleCacheData.getEventNameCaches().get(i).contains(eventAliasName)) {
                            if (index == ruleCacheData.getEventNameCaches().get(i).size()) {
                                flag = true; // 效果：条件组3匹配进来时，前提必须满足条件组1和2才能继续往下走
                                idx = i;
                                break;
                            }
                        }
                    }
                    if (!flag) {
                        RuleCacheDict data = new RuleCacheDict();
                        data.setNext(true);
                        return data;
                    }

                    List<String> eventNameCaches = ruleCacheData.getEventNameCaches().get(idx);
                    Map<String, Object> eventLogCaches = ruleCacheData.getEventLogCaches().get(idx);

                    // 取出当前step 相关的关联条件，进行二次验证数据是否有效
                    Association association = new Event();
                    BeanUtils.copyProperties(ruleCacheData.getMeta().getAssociation(), association);

                    // 同一条日志的这种关联匹配到就没必要了，直接跳过
                    if (ruleCacheData.getAllLogIds().contains(logId)) {
                        return null;
                    }

                    this.appendEventAliasName(eventAliasName, ruleCacheData);
                    if (this.appendEventLog(ruleCacheData, cacheLog, eventAliasName)) {
                        this.appendLog(ruleCacheData, cacheLog, logId);
                    }

                    // 不是最终判定条件的时候需要把还未缓存数据的条件去掉
                    List<Filter> tmpAssociation = new ArrayList<>();
                    if (eventNameCaches.size() != ruleCacheData.getMeta().getEventCount()) {
                        association.getFilter().forEach(filter -> {
                            String leftAliasName = filter.getLeft().split("\\.")[0];
                            String rightAliasName = filter.getRight().split("\\.")[0];
                            if (eventNameCaches.contains(leftAliasName) && eventNameCaches.contains(rightAliasName)) {
                                tmpAssociation.add(filter);
                            }
                        });
                        association.setFilter(tmpAssociation);
                    }

                    // 一个条件都没有的话，说明还没到真正匹配的时候，先缓存着
                    if (association.getFilter().size() != 0) {
                        Condition associationCondition = this.transformEventCondition(eventLogCaches, (Event) association, true);
                        Engine associationEngine = new Engine(associationCondition);
                        if (!associationEngine.evaluate()) {
                            continue;
                        }
                    }

                    this.setCache(cacheKey, ruleCacheData, expireTime, true);
                    // 只有当前是处于判断最后条件的时候才去检查次数是否匹配完了
                    // 判断是否符合设定匹配到的次数
                    for (List<String> eventList : ruleCacheData.getEventNameCaches()) {
                        if (eventList.size() != ruleCacheData.getMeta().getEventCount()) {
                            // 关联发生次数不足
                            return null;
                        }
                    }
                    this.delCache(cacheKey);
                    return ruleCacheData;

                } catch (Exception e) {
                    logger.error("union rule process error", e);
                }
            }
        }

        return null;
    }
}
