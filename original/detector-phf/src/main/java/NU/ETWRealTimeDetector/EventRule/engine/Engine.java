package NU.ETWRealTimeDetector.EventRule.engine;

import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class Engine {

    private Condition condition;
    public boolean isValid;
    public Integer score = 0;

    public Engine(Condition condition) {
        this.condition = condition;
        this.isValid = validate();
    }

    private Boolean validate() {
        return _validate(this.condition);
    }

    private Boolean _validate(Condition condition) {
        if (!condition.checkSize()) {
            return false;
        }

        for (Object arg : condition.getArgs()) {
            if (!(arg instanceof String)) {
                Condition c = (Condition) arg;
                if (!_validate(c)) {
                    return false;
                }
            }
        }

        return true;
    }

    private Boolean eq(Object... args) {
        String left = args[0].toString().toLowerCase();
        String right = args[1].toString().toLowerCase();
        return left.equals(right);
    }

    private Boolean ne(Object... args) {
        String left = args[0].toString().toLowerCase();
        String right = args[1].toString().toLowerCase();
        return !left.equals(right);
    }

    private Boolean contains(Object... args) {
        String left = args[0].toString().toLowerCase();
        String right = args[1].toString().toLowerCase();
        if (StringUtils.isEmpty(right)) {
            return false;
        }

        return left.contains(right);
    }

    private Boolean regex(Object... args) {
        String left = args[0].toString().toLowerCase();
        String right = args[1].toString().toLowerCase();
        if (StringUtils.isEmpty(right)) {
            return false;
        }
        return Pattern.compile(right).matcher(left).find();
    }

    private Boolean _and(Object... args) {
        return Stream.of(args).allMatch(arg -> (Boolean) arg);
    }

    private Boolean _or(Object... args) {
        return Stream.of(args).anyMatch(arg -> (Boolean) arg);
    }

    private Boolean _evaluate(Condition condition) {
        return _evaluate(condition, true);
    }

    private Boolean _evaluate(Condition condition, boolean isFirst) {
        String operator = condition.getOperator().toLowerCase();
        boolean flag = false;

        Object[] args = condition.getArgs().stream().map(arg -> {
            if (arg instanceof String) {
                return arg;
            } else {
                Condition c = (Condition) arg;
                return _evaluate(c, false);
            }
        }).toArray();

        switch (operator) {
            case "eq":
            case "=":
                flag = eq(args);
                break;
            case "ne":
            case "!=":
                flag = ne(args);
                break;
            case "in":
            case "contains":
                flag = contains(args);
                break;
            case "regexp":
            case "regex":
                flag = regex(args);
                break;
            case "and":
                flag = _and(args);
                break;
            case "or":
                flag = _or(args);
                break;
            default:
                // TODO
        }

        // 只有在各条件组进行匹配时才进行分值计算
        if (!isFirst && flag && (operator.equals("and") || operator.equals("or")) ) {
            calculateScore(args, condition.getArgs(), operator);
        }

        return flag;
    }

    private void calculateScore(Object[] args, List<Object> argList, String operator) {
        // 计算分值
        Integer score = 0;
        for (int i = 0; i < args.length; i++) {
            if ((boolean) args[i]) {
                Condition ct = (Condition) argList.get(i);
                score += ct.getScore();
                // 当一个条件组内多个条件满足时，如果是and则累加，如果是or则只取第一个满足的分值
                if (operator.equals("or")) {
                    break;
                }
            }
        }
        this.score += score;
    }

    public Boolean evaluate() {
        return _evaluate(this.condition);
    }

}
