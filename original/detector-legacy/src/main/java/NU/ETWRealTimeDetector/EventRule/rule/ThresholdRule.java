package NU.ETWRealTimeDetector.EventRule.rule;

import NU.ETWRealTimeDetector.EventRule.pojo.Rule;
import NU.ETWRealTimeDetector.EventRule.pojo.RuleCacheDict;
import NU.ETWRealTimeDetector.EventRule.pojo.TimeWindow;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;

public class ThresholdRule extends BaseRule {
    public ThresholdRule(Rule rule, Map<String, Object> log) {
        super(rule, log);
    }

    @Override
    public RuleCacheDict process() {
        String cacheKey = this.getCacheKey();
        TimeWindow timeWindow = this.ruleData.getTimeWindow();
        List<String> groupFields = this.ruleData.getGroupFields();
        if (groupFields.size() == 0) return null;
        Long expireTime = this.getTimeWindowInterval(timeWindow);

        List<String> groupFieldsValue = new ArrayList<>();
        for (String field : groupFields) {
            String value = getFromDict(this.log, field);
            if (!value.isEmpty()) groupFieldsValue.add(value);

        }
        if (groupFields.size() != groupFieldsValue.size()) {
            return null;
        }

        if (groupFieldsValue.size() != 0) {
            String groupValue = StringUtils.join(groupFieldsValue, ",");
            String groupValueHash = DigestUtils.md5Hex(groupValue);
            // cep:1:4:b93050dd191531db78516205e0c99a53 为了防止计数模板和阈值模板缓存池相互影响，阈值模板额外拼接template_type
            cacheKey = String.format("%s:%s:%s", cacheKey, this.ruleCacheDict.getMeta().getTemplateType(), groupValueHash);
        }

        HashMap<String, Object> cacheLog = new HashMap<>(this.log);

        Object[] rst = this.getCacheData(cacheKey, this.ruleCacheDict);
        boolean isExists = (boolean) rst[0];
        RuleCacheDict ruleCacheData = (RuleCacheDict) rst[1];
        String logId = cacheLog.get(this.logIdField).toString();
        if (ruleCacheData.getAllLogIds().contains(logId)) {
            return null;
        }
        this.appendLog(ruleCacheData, cacheLog, logId);

        ruleCacheData.setCount(ruleCacheData.getCount() + this.score);
        if (ruleCacheData.getCount() >= ruleCacheData.getMeta().getCount()) {
            this.delCache(cacheKey);
            return ruleCacheData;
        }
        this.setCache(cacheKey, ruleCacheData, expireTime, isExists);
        return null;
    }
}
