package NU.ETWRealTimeDetector.EventRule.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class RuleCacheDict {

    MetaRule meta;

    List<Map<String, Object>> logs = new ArrayList<>();

    @JsonProperty("all_logs")
    List<Map<String, Object>> allLogs = new ArrayList<>();

    @JsonProperty("all_log_ids")
    List<String> allLogIds = new ArrayList<>();

    @JsonProperty("event_names")
    List<String> eventNames = new ArrayList<>();

    @JsonProperty("event_name_caches")
    List<List<String>> eventNameCaches = new ArrayList<>();

    @JsonProperty("event_log_caches")
    List<Map<String, Object>> eventLogCaches = new ArrayList<>();

    Integer count = 0;

    boolean next = false; // 该字段是用做关联模板未匹配当前规则，让它继续匹配下一个规则的标记

    boolean isStudy = false; // 该字段用来标识是否为学习事件（有一条日志为学习日志即满足）
}
