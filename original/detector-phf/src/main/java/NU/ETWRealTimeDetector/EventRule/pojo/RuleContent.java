package NU.ETWRealTimeDetector.EventRule.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;

@Data
public class RuleContent {
    private Integer count;

    @SerializedName("time_window")
    private TimeWindow timeWindow;
    private List<Event> events;
    private Association association;

    @SerializedName("group_fields")
    private List<String> groupFields;
}
