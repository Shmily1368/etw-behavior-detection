package NU.ETWRealTimeDetector.EventRule.rule;

import NU.ETWRealTimeDetector.EventRule.pojo.Rule;
import NU.ETWRealTimeDetector.EventRule.pojo.RuleCacheDict;

import java.util.Map;

public class GeneralRule extends BaseRule {
    public GeneralRule(Rule rule, Map<String, Object> log) {
        super(rule, log);
    }

    @Override
    public RuleCacheDict process() {
        this.ruleCacheDict.getAllLogs().add(this.log);
        this.ruleCacheDict.getAllLogIds().add(this.log.getOrDefault("id", "").toString());
        return this.ruleCacheDict;
    }
}
