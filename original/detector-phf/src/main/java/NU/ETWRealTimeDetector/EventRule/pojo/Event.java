package NU.ETWRealTimeDetector.EventRule.pojo;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class Event extends Association{
//    private List<Filter> filter;
//    private String operator;

    @SerializedName("alias_name")
    private String aliasName;

    private String name;
}
