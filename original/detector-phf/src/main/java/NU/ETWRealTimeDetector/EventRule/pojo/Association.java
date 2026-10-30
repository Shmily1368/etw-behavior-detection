package NU.ETWRealTimeDetector.EventRule.pojo;

import lombok.Data;

import java.util.List;

@Data
public class Association {
    private List<Filter> filter;
    private String operator;
}
