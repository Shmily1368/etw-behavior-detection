package NU.ETWRealTimeDetector.EventRule.pojo;

import lombok.Data;

@Data
public class Filter {
    private String middle;
    private String left;
    private String right;
    private Integer score = 0;
}
