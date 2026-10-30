package NU.ETWRealTimeDetector.EventRule.rule;

import NU.ETWRealTimeDetector.EventRule.pojo.Rule;
import NU.ETWRealTimeDetector.EventRule.pojo.RuleCacheDict;
import NU.ETWRealTimeDetector.EventRule.pojo.TimeWindow;
import NU.ETWRealTimeDetector.EventRule.pojo.TimeWindowTemplate;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GeneralCountRule extends BaseRule {
    public GeneralCountRule(Rule rule, Map<String, Object> log) {
        super(rule, log);
    }

    @Override
    public RuleCacheDict process() {
        String cacheKey = this.getCacheKey();
        TimeWindow timeWindow = this.ruleData.getTimeWindow();
        List<String> groupFields = this.ruleData.getGroupFields();
        if (groupFields.size() == 0) return null;
//        TimeWindowTemplate trigger = timeWindow.getTrigger();
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
            cacheKey = String.format("%s:%s", cacheKey, groupValueHash); // cep:1:b93050dd191531db78516205e0c99a53
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

        ruleCacheData.setCount(ruleCacheData.getCount() + 1);
        if (ruleCacheData.getCount() >= ruleCacheData.getMeta().getCount()) {
            this.delCache(cacheKey);
            return ruleCacheData;
        }
        this.setCache(cacheKey, ruleCacheData, expireTime, isExists);
        return null;
    }
}
