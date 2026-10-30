package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import com.google.common.base.Objects;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.*;

public class RuleMatch {

    private static Map<String, RuleMatch> clientId2Instance = new HashMap<>();
    private static Logger logger = LoggerFactory.getLogger("rule");
    private static ConcurrentLinkedQueue<RuleMatchInfo> queue = new ConcurrentLinkedQueue<>();
    private static ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();

    public static RuleMatch getInstance(String clientId) {
        RuleMatch instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new RuleMatch(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    static {
        worker.scheduleWithFixedDelay(() -> {
            long currentTimeMillis = System.currentTimeMillis();
            List<RuleMatchInfo> ruleMatchInfos = new ArrayList<>();
            while (true) {
                RuleMatchInfo ruleMatchInfo = queue.peek();
                if (ruleMatchInfo == null) {
                    break;
                }

                if (currentTimeMillis < ruleMatchInfo.delayProcessTime) {
                    break;
                }

                ruleMatchInfos.add(ruleMatchInfo);
                queue.remove();
            }

            if (ruleMatchInfos.isEmpty()) {
                logger.info("job run at {} data 0", currentTimeMillis);
                return;
            } else {
                logger.info("job run at {} data {}", currentTimeMillis, ruleMatchInfos.size());
            }

            List<HashMap<String, String>> list = new ArrayList<>();
            ruleMatchInfos.forEach(r -> {
                ConcurrentSkipListSet<Process> processSet = ProcessTable.getInstance(r.clientId).getProcessId2ProcessList().get(r.processId);
                if (processSet == null) {
                    logger.info("can not find process by processId and timestamp  {}", r.toString());
                    return;
                }

                Optional<Process> processOptional = processSet.stream()
                        .filter(p -> p.getProcessId() == r.processId && p.getStartTime() == r.timestamp && p.getFileName().toLowerCase().equals(r.imageFileName.toLowerCase()))
                        .findFirst();

                if (!processOptional.isPresent()) {
                    logger.info("can not find process by processId and timestamp  {}", r.toString());
                    return;
                }


                processSet = ProcessTable.getInstance(r.clientId).getProcessId2ProcessList().get(r.parentProcessId);

                Optional<Process> parentProcessOptional = processSet.stream()
                        .filter(p -> p.getProcessId() == r.parentProcessId && p.getFileName().toLowerCase().equals(r.parentProcessName.toLowerCase()))
                        .findFirst();


                Process process = processOptional.get();

                HashMap<String, String> map = new HashMap<>(11);
                map.put("client_id", r.clientId);
                map.put("rule_id", r.ruleId);
                map.put("event_name", r.eventName);
                map.put("process_id", String.valueOf(r.processId));
                map.put("process_name", r.imageFileName);
                map.put("process_path", process.hasProcessName() ? process.getProcessName() : r.imageFileName);
                map.put("command_line", r.commandLine);
                map.put("time_stamp", String.valueOf(r.timestamp));

                if (parentProcessOptional.isPresent()) {
                    Process parentProcess = parentProcessOptional.get();
                    parentProcess.ensureFileName();

                    map.put("parent_process_id", String.valueOf(r.parentProcessId));
                    map.put("parent_process_name", parentProcess.getFileName());
                    map.put("parent_process_path", parentProcess.hasProcessName() ? parentProcess.getProcessName() : "");
                    map.put("parent_process_command_line", parentProcess.getCommandLine());
                } else {
                    logger.info("can not find parent process by parentProcessId and parentProcessId  {}", r.toString());

                    map.put("parent_process_id", "");
                    map.put("parent_process_name", "");
                    map.put("parent_process_path", "");
                    map.put("parent_process_command_line", "");
                }

                list.add(map);
            });

            Reporter.reportRuleMatch(list);

        }, 10, 10, TimeUnit.SECONDS);
    }

    private String clientId;

    private Gson gson = new Gson();

    public RuleMatch(String clientId) {
        this.clientId = clientId;
    }

    public void processSimpleRuleEvent(int ruleId, String eventName, String params, long timestamp) {
        // 这个事件有可能在ProcessStart之前，之后，或者ImageLoad之后
        // timestamp 跟 ProcessStart的 timestamp 相同

        // 收到事件 先放到队列，每个事件设置一个过期时间， 启动一个线程，每10s执行一次，从队列中取出过期的数据，然后上报
        // 极端情况下会出现，Process已被移除的情况

        HashMap<String, String> json = fromJson(params);
        if (params == null) {
            return;
        }

        int processId = Integer.valueOf(json.getOrDefault("ProcessId", "0"));
        int parentProcessId = Integer.valueOf(json.getOrDefault("ParentId", "0"));
        String imageFileName = json.getOrDefault("ImageFileName", "");
        String commandLine = json.getOrDefault("CommandLine", "");
        String parentProcessName = json.getOrDefault("ParentProcessName", "");

        queue.offer(new RuleMatchInfo(
                clientId,
                String.valueOf(ruleId),
                eventName,
                processId,
                parentProcessId,
                imageFileName,
                commandLine,
                parentProcessName,
                timestamp));
        logger.info("add rule match to queue clientId:{} pid:{} ruleId:{} eventName:{} timestamp:{}", clientId, processId, ruleId, eventName, timestamp);
    }

    private HashMap<String, String> fromJson(String json) {
        try {
            Type type = new TypeToken<HashMap<String, String>>() {
            }.getType();
            HashMap<String, String> data = gson.fromJson(json, type);
            return data;
        } catch (Exception e) {
            logger.error("解析json失败", e);
            return null;
        }
    }

    class RuleMatchInfo {
        private String clientId;
        private String ruleId;
        private String eventName;
        private Integer processId;
        private Integer parentProcessId;
        private String imageFileName;
        private String commandLine;
        private String parentProcessName;
        private Long timestamp;
        private Long delayProcessTime;

        public RuleMatchInfo(String clientId, String ruleId, String eventName, Integer processId, Integer parentProcessId, String imageFileName, String commandLine, String parentProcessName, Long timestamp) {
            this.clientId = clientId;
            this.ruleId = ruleId;
            this.eventName = eventName;
            this.processId = processId;
            this.parentProcessId = parentProcessId;
            this.imageFileName = imageFileName;
            this.commandLine = commandLine;
            this.parentProcessName = parentProcessName;
            this.timestamp = timestamp;
            this.delayProcessTime = System.currentTimeMillis() + 10000;//10s
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RuleMatchInfo that = (RuleMatchInfo) o;
            return Objects.equal(ruleId, that.ruleId) &&
                    Objects.equal(eventName, that.eventName) &&
                    Objects.equal(processId, that.processId) &&
                    Objects.equal(parentProcessId, that.parentProcessId) &&
                    Objects.equal(imageFileName, that.imageFileName) &&
                    Objects.equal(commandLine, that.commandLine) &&
                    Objects.equal(parentProcessName, that.parentProcessName) &&
                    Objects.equal(timestamp, that.timestamp);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(ruleId, eventName, processId, parentProcessId, imageFileName, commandLine, parentProcessName, timestamp);
        }

        @Override
        public String toString() {
            return "RuleMatchRunnable{" +
                    "ruleId='" + ruleId + '\'' +
                    ", eventName='" + eventName + '\'' +
                    ", processId=" + processId +
                    ", parentProcessId=" + parentProcessId +
                    ", imageFileName='" + imageFileName + '\'' +
                    ", commandLine='" + commandLine + '\'' +
                    ", parentProcessName='" + parentProcessName + '\'' +
                    ", timestamp=" + timestamp +
                    '}';
        }
    }
}
