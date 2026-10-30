package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class Ransomware {

    private static Cache<String, String> slidingWindow = Caffeine.newBuilder()
            .initialCapacity(3)
            .maximumSize(1000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    public static void reportRansomware(String clientId, Integer processId, Integer ppid, String processName, String parentProcessName, String extraInfo, Long timestamp) {
        String key = String.format("%s_%s_%s", clientId, processId, processName);

        String value = slidingWindow.getIfPresent(key);
        if (value == null) {
            Process process = ProcessTable.getInstance(clientId).getProcessOrCreateOneIfNotExist(processId, timestamp);
            String eventId = UUID.nameUUIDFromBytes(String.valueOf(process.getUuid()).getBytes()).toString();
            String processPath = process.hasProcessName() ? process.getProcessName() : processName;
            // 上报
            Reporter.reportRansomware(eventId, clientId, processId, ppid, processName, processPath, process.getCommandLine(), process.getMd5(), parentProcessName, extraInfo, timestamp);
            slidingWindow.put(key, key);
        }
    }

    private static String getProcessNameFromProcessPath(String processPath) {
        return processPath;
    }

}
