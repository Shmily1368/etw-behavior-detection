package NU.ETWRealTimeDetector.Pojo;

import NU.ETWRealTimeDetector.SysConfig;

import java.util.concurrent.atomic.AtomicInteger;

public class SensitiveProgram2Info {
    private static final Integer reportInterval = SysConfig.getInteger("SensitiveProgramReportInterval", 5 * 60);
    // 上次上报时间
    Long lastReportTime;
    // 该命令的执行
    AtomicInteger count;

    public SensitiveProgram2Info() {
        lastReportTime = 0L;
        this.count = new AtomicInteger();
    }

    public SensitiveProgram2Info(Long lastReportTime, Integer count) {
        this.lastReportTime = Long.valueOf(lastReportTime);
        this.count = new AtomicInteger(count);
    }

    public void increment() {
        count.incrementAndGet();
    }

    public boolean needReport(long timestamp) {
        // 间隔一段时间上报
        if (timestamp > lastReportTime.longValue() + reportInterval * 1000 * 1000000L) {
            lastReportTime = timestamp;
            return true;
        }
        return false;
    }

    public Long getLastReportTime() {
        return lastReportTime;
    }

    public Integer getCount() {
        return count.get();
    }

    @Override
    public String toString() {
        return "SensitiveProgram2Info{lastReportTime=" + lastReportTime + ", count=" + count + '}';
    }
}
