package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Pojo.ThreatInfo;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.IPParser;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.roaringbitmap.RoaringBitmap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ThreatIntelligence {
    private static RoaringBitmap rb;

    private static Map<String, ThreatIntelligence> clientId2Instance = new HashMap<>();

    private static Logger logger = LoggerFactory.getLogger("threat");
    private static final int ipExternalSlidingWindow = SysConfig.getInteger("IpExternalSlidingWindowThreshold", 10);
    private static ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
    private static ConcurrentLinkedQueue<ThreatInfo> queue = new ConcurrentLinkedQueue<>();

    static {
        // 1分钟执行一次，上报蜜罐机外连IP
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            List<HashMap<String, String>> list = new ArrayList<>(queue.size());
            while (true) {
                ThreatInfo externalIpInfo = queue.poll();
                if (externalIpInfo == null) {
                    break;
                }
                list.add(externalIpInfo.toMap());
            }

            // 上报
            Reporter.reportThreatIntelligence(list);
        }, 1, 1, TimeUnit.MINUTES);
    }

    public static ThreatIntelligence getInstance(String clientId) {
        ThreatIntelligence instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new ThreatIntelligence(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    public static void init() {
        DataInputStream in = null;
        long st = System.currentTimeMillis();
        String file1 = "rb.bin";
        try {
            in = new DataInputStream(new FileInputStream(file1));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        rb = new RoaringBitmap();
        try {
            rb.deserialize(in);
        } catch (IOException e) {
            e.printStackTrace();
        }

        long et = System.currentTimeMillis();
        long time = et - st;
        System.out.println("load rb:" + time);
    }

    private String clientId;

    private static Cache<String, String> slidingWindow = Caffeine.newBuilder()
            .initialCapacity(1000)
            .maximumSize(1000000)
            .expireAfterAccess(ipExternalSlidingWindow, TimeUnit.MINUTES)
            .build();

    public ThreatIntelligence(String clientId) {
        this.clientId = clientId;
    }


    public void checkIp(int processId, long ip, String protocol, long timestamp) {
        if (rb == null) {
            return;
        }

        boolean isThreat = false;
        if (ip <= Integer.MAX_VALUE) {
            isThreat = rb.contains(Long.valueOf(ip).intValue());
        } else {
            Long diff = ip - Integer.MAX_VALUE;
            int value = Integer.MAX_VALUE + diff.intValue();
            isThreat = rb.contains(value);
        }

        if (!isThreat) {
            return;
        }

        Process process = ProcessTable.getInstance(clientId).getProcess(processId, timestamp);
        if (process == null) {
            return;
        }

        if (!process.hasProcessName()) {
            return;
        }

        String destIp = IPParser.parseIpAddress(ip);

        // 10分钟滑动窗口合并
        String key = String.format("%s_%s_%s", clientId, process.getProcessId(), destIp);
        String value = slidingWindow.getIfPresent(key);
        if (value != null) {
            return;
        }

        logger.info("{} {} {} {}", process, destIp, protocol, timestamp);

        // 因为事件乱序原因 会创建多个Process对象，部分情况下会出现，fileName为空的清空，此时需要手动补充fileName
        if (process.getFileName().isEmpty()) {
            process.ensureFileName();
            if (process.getFileName().isEmpty()) {
                return;
            }
        }

        // report
        ThreatInfo threatInfo = new ThreatInfo(clientId, destIp, process.getFileName(), process.getProcessName(), String.valueOf(processId), String.valueOf(System.currentTimeMillis()));
        queue.offer(threatInfo);
        slidingWindow.put(key, key);

    }

}
