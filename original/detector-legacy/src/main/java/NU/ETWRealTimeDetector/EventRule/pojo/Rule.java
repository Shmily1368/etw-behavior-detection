package NU.ETWRealTimeDetector.EventRule.pojo;

import com.alibaba.fastjson.annotation.JSONField;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class Rule {
    private String id;
    private Integer level;

    @SerializedName("template_type")
    private Integer templateType;
    private String name;

    @SerializedName("event_id")
    private String eventId;

    @SerializedName("alarm_stag")
    private String alarmStag;

    @SerializedName("alarm_type")
    private String alarmType;

    private Integer enable;

    private RuleContent rule;

    private Integer behavior;
    private String description;
    private String solution;

    // 从redis取出来时做临时储存用
//    private String rule;
}
