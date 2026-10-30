package NU.ETWRealTimeDetector.EventRule.pojo;

import lombok.Data;

@Data
public class TimeWindow {
//    private TimeWindowTemplate trigger;
//    private TimeWindowTemplate merge;
    private Long interval;
    private String unit;
}
