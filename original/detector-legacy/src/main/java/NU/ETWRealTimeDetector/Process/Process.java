package NU.ETWRealTimeDetector.Process;

import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Util.StringUtil;
import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

public class Process implements Comparable<Process> {
    private static final Logger logger = LoggerFactory.getLogger(Process.class);
    public static AtomicInteger counter = new AtomicInteger(0);
    private static Neo4jClient neo4jClient = Neo4jClient.getInstance();


    private String clientId;
    private int uuid;
    private int processId;
    private long startTime;
    private long endTime;
    private long anyMiddleTime;
    private String fileName = "";
    private String processName = "uninitialized_process";
    private String commandLine = "";
    private long updateTime = 0;
    private long lastNetworkTimestamp = 0;
    private String md5 = "";

    public Process(String clientId, int processId, int uuid, String commandLine) {
        this.clientId = clientId;
        this.processId = processId;
        this.uuid = uuid;
        this.commandLine = commandLine;
    }

    public Process(String clientId, int processId, String commandLine) {
        this(clientId, processId, counter.incrementAndGet(), commandLine);
        neo4jClient.addProcessNode(this);
        if (counter.get() % 10000 == 0) {
            Snapshot.saveUuid(counter.get());
        }
        logger.info(String.format("Process %s on client %s created", this.toString(), clientId));
    }

    public Process(String clientId, int processId, boolean isRoot) {
        this(clientId, processId, "");
        this.startTime = 0;
        this.endTime = 1;
        this.processName = "root";
    }

    public Process(int uuid, String clientId, int processId, long startTime, long endTime, long anyMiddleTime, String fileName, String processName, String commandLine, long updateTime) {
        this.uuid = uuid;
        this.clientId = clientId;
        this.processId = processId;
        this.startTime = startTime;
        this.endTime = endTime;
        this.anyMiddleTime = anyMiddleTime;
        this.fileName = fileName;
        this.processName = processName;
        this.commandLine = commandLine;
        this.updateTime = updateTime;
    }

    boolean hasRightProcessName() {
        return !"uninitialized_process".equals(processName) && StringUtil.isPathRight(processName);
    }

    public boolean hasProcessName() {
        return !"uninitialized_process".equals(processName);
    }

    public int getProcessId() {
        return processId;
    }

    public int getUuid() {
        return uuid;
    }

    public String getProcessName() {
        return processName;
    }

    public void setUpdateTime(long time) {
        this.updateTime = time;
    }

    public long getUpdateTime() {
        return this.updateTime;
    }

    public void setLastNetworkTimestamp(long timestamp) {
        this.lastNetworkTimestamp = timestamp;
    }

    public long getLastNetworkTimestamp() {
        return this.lastNetworkTimestamp;
    }

    public boolean isDownload(long timestamp) {
        // 判断 FileIoWrite 时间是否 在 最近一次网络事件的一分钟内执行的
        return timestamp < this.lastNetworkTimestamp + (60 * 1000 * 1000000L);
    }

    public String getCommandLine() {
        return commandLine;
    }

    public void setProcessName(String processName) {
        neo4jClient.updateProcessNode(clientId, uuid, "name", processName);
        this.processName = processName;
        logger.info(String.format("Process %s on client %s get name", this.toString(), clientId));
    }

    public void setCollectorStartTime(Long collectorStartTime) {
        neo4jClient.updateProcessNode(clientId, uuid, "collectorStartTime", collectorStartTime);
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getMd5() {
        return this.md5;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public long getAnyMiddleTime() {
        return anyMiddleTime;
    }

    public String getFileName() {
        return fileName;
    }

    public String getClientId() {
        return clientId;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
        neo4jClient.updateProcessNode(clientId, uuid, "start", startTime / 1000000L);
    }

    public void setEndTime(long endTime) {
        this.endTime = endTime;
        neo4jClient.updateProcessNode(clientId, uuid, "end", endTime / 1000000L);
    }

    public void setAnyMiddleTime(long anyMiddleTime) {
        this.anyMiddleTime = anyMiddleTime;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void ensureFileName() {
        if (fileName.isEmpty() && hasProcessName()) {
            int lastIndexOf = processName.lastIndexOf("\\");
            if (lastIndexOf > 0 && lastIndexOf + 1 < processName.length())
                fileName = processName.substring(lastIndexOf + 1);
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        Process process = (Process) o;

        return uuid == process.uuid;
    }

    @Override
    public int hashCode() {
        return uuid;
    }

    @Override
    public String toString() {
        return String.format("pid_%d_%s_uuid_%d", processId, processName, uuid);
    }

    @Override
    public int compareTo(Process o) {
        long o1Time = startTime > 0 ? startTime : anyMiddleTime;
        long o2Time = o.getStartTime() > 0 ? o.getStartTime() : o.getAnyMiddleTime();

        if (o1Time < o2Time) {
            return -1;
        } else if (o1Time > o2Time) {
            return 1;
        }
        return 0;
    }
}
