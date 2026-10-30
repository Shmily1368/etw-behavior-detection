package NU.ETWRealTimeDetector.EventRule.pojo;

import lombok.Data;

import java.util.List;

@Data
public class MetaRule {
    private String id;
    private String name;
    private String description;
    private String solution;
    private Integer templateType;
    private String eventId;
    private Integer level;
    private Integer behavior;
    private Integer count;
    private List<String> groupFields;
    private TimeWindow timeWindow;
    private Association association;
    private List<Event> events;
    private Integer eventCount;
}
