package NU.ETWRealTimeDetector.KafkaProcessor.Virus;

/**
 * @author lisq
 * @date 2022/4/28 11:00 上午
 */
public class DefenseWay {

    private String logId;

    private Integer terminate;

    private Integer count = 0;

    public String getLogId() {
        return logId;
    }

    public void setLogId(String logId) {
        this.logId = logId;
    }

    public Integer getTerminate() {
        return terminate;
    }

    public void setTerminate(Integer terminate) {
        this.terminate = terminate;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }
}
