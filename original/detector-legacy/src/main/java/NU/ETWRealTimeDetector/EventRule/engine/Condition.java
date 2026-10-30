package NU.ETWRealTimeDetector.EventRule.engine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Condition {
    // 操作符
    private String operator;
    // 参数
    private List<Object> args = new ArrayList<>();
    // 分值
    private Integer score = 0;

    public boolean checkSize() {
        if (!Pattern.matches("^=|eq|!=|ne|in|contains|regexp|regex|and|AND|or|OR$", this.getOperator()) || this.getArgs().size() == 0) {
            return false;
        }
        return true;
    }
}
