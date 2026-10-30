package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Util.IPParser;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class HoneyPot {
    private static final Logger logger = LoggerFactory.getLogger(MessageProcessor.class);
    private String clientId;
    private Gson gson = new Gson();

    public HoneyPot(String clientId) {
        this.clientId = clientId;
    }

    private static Map<String, HoneyPot> clientId2Instance = new HashMap<>();

    private HashMap<String, UserLogonFailedReportInfo> userLogonFailedReportInfoHashMap = new HashMap<>();

    private Cache<String, UserLogonSuccessReportInfo> userLogonSuccessReportInfoCache = Caffeine.newBuilder()
            .initialCapacity(3)
            .maximumSize(500)
            .expireAfterWrite(20, TimeUnit.SECONDS)
            .build();

    public static HoneyPot getInstance(String clientId) {
        HoneyPot honeyPot = clientId2Instance.get(clientId);

        if (honeyPot == null) {
            honeyPot = new HoneyPot(clientId);
        }
        clientId2Instance.put(clientId, honeyPot);

        return honeyPot;
    }

    public void reportUserLogonSuccess(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        String logonType = data.get("LogonType");
        if (logonType.equals("5")) {
            // 忽略5
            return;
        }

        Integer processId = Integer.valueOf(data.getOrDefault("ProcessId", "-1"));
        String processName = data.getOrDefault("ProcessName", "");
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        String subjectUserName = data.getOrDefault("SubjectUserName", "");
        String subjectDomainName = data.getOrDefault("SubjectDomainName", "");
        String workStationName = data.getOrDefault("WorkstationName", "");
        String ipAddress = data.getOrDefault("IpAddress", "");
        String ipPort = data.getOrDefault("IpPort", "");

        if (ipAddress.equals("-")) {
            return;
        }

        // 内联ip过滤
        if (IPParser.isIp(ipAddress)) {
            //Long saddr = IPParser.ipToLong(ipAddress);
            if (MessageProcessor.excludeInternalIpList.stream().anyMatch(i -> i.isInRange(ipAddress))) {
                return;
            }
        }

        String key = String.format("ip_%s_port_%s_targetUserName_%s", ipAddress, ipPort, targetUserName);
        UserLogonSuccessReportInfo reportInfo = userLogonSuccessReportInfoCache.get(key, (k) -> new UserLogonSuccessReportInfo(ipAddress, ipPort, targetUserName));
        if (!reportInfo.needReport(timestamp)) {
            return;
        }

        Reporter.reportUserLogonSuccess(clientId,
                logonType,
                processId,
                processName,
                targetUserName,
                targetDomainName,
                subjectUserName,
                subjectDomainName,
                workStationName,
                ipAddress,
                ipPort,
                timestamp);
    }

    public void reportUserLogonFailed(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        String logonType = data.get("LogonType");
        Integer processId = Integer.valueOf(data.getOrDefault("ProcessId", "-1"));
        String processName = data.getOrDefault("ProcessName", "");
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        String subjectUserName = data.getOrDefault("SubjectUserName", "");
        String subjectDomainName = data.getOrDefault("SubjectDomainName", "");
        String workStationName = data.getOrDefault("WorkstationName", "");
        String ipAddress = data.getOrDefault("IpAddress", "");
        String ipPort = data.getOrDefault("IpPort", "");
        String status = data.getOrDefault("Status", "");

        // 内联ip过滤
        if (IPParser.isIp(ipAddress)) {
            //Long saddr = IPParser.ipToLong(ipAddress);
            if (MessageProcessor.excludeInternalIpList.stream().anyMatch(i -> i.isInRange(ipAddress))) {
                return;
            }
        }

        String key = String.format("ip_%s_status_%s", ipAddress, status);
        UserLogonFailedReportInfo reportInfo = userLogonFailedReportInfoHashMap.getOrDefault(key, new UserLogonFailedReportInfo(ipAddress, status));
        userLogonFailedReportInfoHashMap.putIfAbsent(key, reportInfo);
        reportInfo.count.incrementAndGet();
        if (!reportInfo.needReport(timestamp)) {
            return;
        }

        Reporter.reportUserLogonFailed(clientId,
                logonType,
                processId,
                processName,
                targetUserName,
                targetDomainName,
                subjectUserName,
                subjectDomainName,
                workStationName,
                ipAddress,
                ipPort,
                status,
                timestamp);

    }

    public void reportUserLogonOff(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        // 当EventId为 4647时 没有LogonType，此时默认 LogonType为2
        String logonType = data.getOrDefault("LogonType", "2");
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        Reporter.reportUserLogOff(clientId, targetUserName, targetDomainName, logonType, timestamp);
    }

    public void reportCreateUser(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        String subjectUserName = data.getOrDefault("SubjectUserName", "");
        String subjectDomainName = data.getOrDefault("SubjectDomainName", "");
        Reporter.reportCreateUser(clientId, targetUserName, targetDomainName, subjectUserName, subjectDomainName, timestamp);
    }

    public void reportDeleteUser(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        String subjectUserName = data.getOrDefault("SubjectUserName", "");
        String subjectDomainName = data.getOrDefault("SubjectDomainName", "");
        Reporter.reportDeleteUser(clientId, targetUserName, targetDomainName, subjectUserName, subjectDomainName, timestamp);
    }

    public void reportChangeUserPassword(String json, Long timestamp) {
        HashMap<String, String> data = fromJson(json);
        String targetUserName = data.getOrDefault("TargetUserName", "");
        String targetDomainName = data.getOrDefault("TargetDomainName", "");
        String subjectUserName = data.getOrDefault("SubjectUserName", "");
        String subjectDomainName = data.getOrDefault("SubjectDomainName", "");
        Reporter.reportChangeUserPassword(clientId, targetUserName, targetDomainName, subjectUserName, subjectDomainName, timestamp);
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

    class UserLogonFailedReportInfo {
        String ipAddress;
        String status;

        Long lastEventTime;
        AtomicLong count;

        UserLogonFailedReportInfo(String ipAddress, String status) {
            this.ipAddress = ipAddress;
            this.status = status;
            this.lastEventTime = 0L;
            this.count = new AtomicLong(0);
        }

        boolean needReport(Long eventTime) {
            eventTime = eventTime / 1000000;// 毫秒

            long now = System.currentTimeMillis();
            boolean needReport = now - lastEventTime > 60000;
            this.lastEventTime = eventTime;
            return needReport;
        }
    }

    class UserLogonSuccessReportInfo {
        String ipAddress;
        String port;
        String targetUserName;

        Long lastEventTime;

        UserLogonSuccessReportInfo(String ipAddress, String port, String targetUserName) {
            this.ipAddress = ipAddress;
            this.port = port;
            this.targetUserName = targetUserName;
            lastEventTime = 0L;
        }

        boolean needReport(Long eventTime) {
            eventTime = eventTime / 1000000;// 毫秒

            long now = System.currentTimeMillis();
            boolean needReport = now - lastEventTime > 20000;
            this.lastEventTime = eventTime;
            return needReport;
        }
    }

}
