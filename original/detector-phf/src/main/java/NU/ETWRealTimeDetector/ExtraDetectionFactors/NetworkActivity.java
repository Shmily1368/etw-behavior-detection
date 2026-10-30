package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Cache.IPInfo;
import NU.ETWRealTimeDetector.Cache.ProcessNetworkInfo;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Pojo.ExternalIpInfo;
import NU.ETWRealTimeDetector.Pojo.etwThread;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import NU.ETWRealTimeDetector.Util.IPParser;
import NU.ETWRealTimeDetector.Util.NetworkOperation;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class NetworkActivity {
    private static final Logger logger = LoggerFactory.getLogger(NetworkActivity.class);
    private static final int ipExternalSlidingWindow = SysConfig.getInteger("IpExternalSlidingWindowThreshold", 10);
    private static Logger honeyPotDetailLogger = LoggerFactory.getLogger("honeypot_detail");
    private static Map<String, NetworkActivity> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = false;

    final IPInfo ipInfoTemp = new IPInfo(1L);

    public static NetworkActivity getInstance(String clientId) {
        NetworkActivity instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new NetworkActivity(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    public static void removeClient(String clientId) {
        if (clientId2Instance.containsKey(clientId)) {
            clientId2Instance.remove(clientId);
        }
    }

    private String clientId;
    private ProcessTable processTable;
    private DetectionFramework framework;
    private Cryptomining cryptomining;
    private IDumper dumpEvent;
    private Map<Integer, ProcessNetworkInfo> ipMap;

    private ProcessInjection processInjection;

    private HashMap<String, ReportInfo> honeypotReports = new HashMap<>();
    private static ConcurrentLinkedQueue<ExternalIpInfo> externalIpInfoQueue = new ConcurrentLinkedQueue<>();
    private static ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();

    private static Cache<String, String> slidingWindow = Caffeine.newBuilder()
            .initialCapacity(1000)
            .maximumSize(1000000)
            .expireAfterAccess(ipExternalSlidingWindow, TimeUnit.MINUTES)
            .build();

    private static Cache<String, HashSet<String>> destCache = Caffeine.newBuilder()
            .initialCapacity(1000)
            .maximumSize(1000000)
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .build();


    static {
        // 1分钟执行一次，上报蜜罐机外连IP
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            List<HashMap<String, String>> list = new ArrayList<>(externalIpInfoQueue.size());
            while (true) {
                ExternalIpInfo externalIpInfo = externalIpInfoQueue.poll();
                if (externalIpInfo == null) {
                    break;
                }
                list.add(externalIpInfo.toMap());
            }

            // 上报
            Reporter.reportExternalIp(list);
        }, 1, 1, TimeUnit.MINUTES);
    }

    public NetworkActivity(String clientId) {
        this.clientId = clientId;
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        cryptomining = Cryptomining.getInstance(clientId);
        processInjection = ProcessInjection.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        ipMap = new HashMap<>();
        new File("ipInfo/" + clientId + "/").mkdirs();
    }

    public void addNetworkActivity(int processId, int threadId, long timestamp, Long sourceIp, int sourcePort, final Long destinationIp, int destinationPort, int size, NetworkOperation operation) {
        // start dump
        if (TURN_ON_DUMP) {
            Map<String, Object> argument = new HashMap<>();
            argument.put("SourceIP", sourceIp);
            argument.put("SourcePort", sourcePort);
            argument.put("DestinationIp", destinationIp);
            argument.put("DestinationPort", destinationPort);
            argument.put("Size", size);
            argument.put("Op", operation);
            dumpEvent.writeToDump("NetworkActivity", processId, timestamp, argument);
        }
        // end dump

        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        //Process realProcess = processInjection.guessRealProcess(process);
        Process realProcess = processInjection.getRealProcess(process, threadId);

        // save ip
        ProcessNetworkInfo processNetworkInfo = ipMap.get(realProcess.getUuid());

        if (processNetworkInfo == null) {
            processNetworkInfo = new ProcessNetworkInfo(processId);
        }

        ipInfoTemp.setSourceIp(destinationIp);
        if (!processNetworkInfo.existIp(ipInfoTemp)) {
            processNetworkInfo.addIp(destinationIp, timestamp / 1000000);
            ipMap.put(realProcess.getUuid(), processNetworkInfo);
            logger.debug(String.format("pid_%d_uuid_%d ip %d timestamp %d ", processId, realProcess.getUuid(), destinationIp, timestamp));
        }

        cryptomining.checkIp(process, destinationIp, timestamp);
        LabelForCS label = new LabelForCS(LabelType.PT1, clientId, realProcess.getUuid(), timestamp, "");
        framework.addLabel(label);
        realProcess.setLastNetworkTimestamp(timestamp);

        if (operation.equals(NetworkOperation.NETWORK_CONNECT)
                && !IPParser.isPublicIp(destinationIp)
                && IPParser.isCommonPort(destinationPort)) {

            // 每分钟聚合
            String key = String.format("%s_%d_%d", clientId, realProcess.getUuid(), timestamp / 1000000 / 1000 / 60);

            HashSet<String> set = destCache.getIfPresent(key);
            if (set == null) {
                set = new HashSet<>();
                destCache.put(key, set);
            }

            String ipPort = String.format("%d_%d", destinationIp, destinationPort);
            if (!set.contains(ipPort)) {
                set.add(ipPort);
                if (set.size() == 5) {
                    LabelForCS portScanLabel = new LabelForCS(LabelType.PT43, clientId, realProcess.getUuid(), timestamp, "");
                    framework.addLabel(portScanLabel);
                }
            }
        }

    }

    public void reportAccessExternalIp(int processId, long timestamp, Long sourceIp, int sourcePort, Long destinationIp, int destinationPort, String protocol) {
        // 排除 127.0.0.1 239.255.255.250
        if (destinationIp == 16777343L || destinationIp == 4211081199L) {
            return;
        }
        // 外联ip排除
        String destIp = IPParser.parseIpAddress(destinationIp);
        if (MessageProcessor.excludeExternalIpList.stream().anyMatch(i -> i.isInRange(destIp))) {
            return;
        }

        // 外联ip排除广播地址
        if (IPParser.isBroadcastAddress(destIp)) {
            return;
        }

        // 判断配置是否只上报内网ip，判断是否为外网IP，外联外网IP不上报
        if (MessageProcessor.intranet_mode && IPParser.isPublicIp(destinationIp)) {
            return;
        }

        Process process = processTable.getProcess(processId, timestamp);
        if (process == null) {
            return;
        }
        if (process.getProcessId() != 4 && !process.hasProcessName()) {
            return;
        }

        ExternalIpInfo externalIpInfo = new ExternalIpInfo(clientId, process, timestamp, sourceIp, sourcePort, destinationIp, destinationPort, protocol);

        // 10分钟滑动窗口合并
        String key = String.format("%s_%s_%s", clientId, process.getProcessName(), destIp);
        String value = slidingWindow.getIfPresent(key);
        if (value != null) {
            return;
        }

        // 判断进程是否在白名单
        if (isWhiteList(process.getFileName())) {
            return;
        }

        honeyPotDetailLogger.info("clientId {} pid {} timestamp {} daddr {} filename {} processname {}", clientId, processId, timestamp, destIp, process.getFileName(), process.getProcessName());
        if (!process.hasProcessName() && process.getFileName().isEmpty()) {
            ConcurrentSkipListSet<Process> processSet = processTable.getProcessId2ProcessList().getOrDefault(processId, new ConcurrentSkipListSet<>());
            for (Process p : processSet) {
                honeyPotDetailLogger.info("pid {} uuid {} filename {} processname {} startTime {} endTime {} middleTime {} ", p.getProcessId(), p.getUuid(), p.getFileName(), p.getProcessName(), p.getStartTime(), p.getEndTime(), p.getAnyMiddleTime());
            }
            return;
        }

        // 加入到队列
        externalIpInfoQueue.offer(externalIpInfo);
        slidingWindow.put(key, key);

    }

    private boolean isWhiteList(String imageFileName) {
        boolean result = true;
        if (imageFileName == null || imageFileName.isEmpty()) {
            return true;
        }

        return MessageProcessor.whiteAppList.contains(imageFileName.toLowerCase().hashCode());
        /*

        if (result || processName.equals("uninitialized_process")) {
            return result;
        }

        int index = processName.lastIndexOf("\\");
        if (index == -1) {
            return result;
        }

        String path = processName.substring(0, index);
        return MessageProcessor.whiteAppList.contains(path.toLowerCase().hashCode());
         */
    }

    public void reportPortAccessed(int processId, long timestamp, Long sourceIp, int sourcePort, Long destinationIp, int destinationPort, String protocol) {
        // 内联IP排除
        String daddr = IPParser.parseIpAddress(destinationIp);
        if (MessageProcessor.excludeInternalIpList.stream().anyMatch(s -> s.isInRange(daddr))) {
            return;
        }

        String saddr = IPParser.parseIpAddress(sourceIp);

        // 外联ip排除广播地址
        if (IPParser.isBroadcastAddress(saddr)) {
            return;
        }

        // 判断端口
        int sport = IPParser.parsePort(sourcePort);
        if (!MessageProcessor.portList.contains(sport)) {
            return;
        }

        // 合并
        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        String key = String.format("uuid_%d_sport_%d_daddr_%s_%s", process.getUuid(), sport, daddr, protocol);

        ReportInfo reportInfo = honeypotReports.getOrDefault(key, new ReportInfo(sport, daddr));
        honeypotReports.putIfAbsent(key, reportInfo);
        reportInfo.count.incrementAndGet();
        if (!reportInfo.needReport(timestamp)) {
            return;
        }

        int dport = IPParser.parsePort(destinationPort);
        Reporter.reportNetwork(clientId, process, saddr, sport, daddr, dport, protocol, reportInfo.count.get(), timestamp);
        reportInfo.count.set(0);
    }

    public void removeProcessIpInfo(Process process) {
        ProcessNetworkInfo processNetworkInfo = ipMap.get(process.getUuid());
        if (processNetworkInfo != null && !processNetworkInfo.isEmpty()) {
            // save to file
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(String.format("ipInfo/%s/%d", process.getClientId(), process.getUuid())))) {
                oos.writeObject(processNetworkInfo);
                oos.flush();
                logger.info(String.format(" process %s is end. IpInfo has been persisted ipInfo/%d.", process, process.getUuid()));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        ipMap.remove(process.getUuid());
    }

    public void saveIpInfoToJson(Process process) {
        String fileName = Reporter.getIpInfoFileName(process.getClientId(), String.valueOf(process.getProcessId()), String.valueOf(process.getUuid()));
        String json = getIpInfoJson(process);
        save(fileName, json);
    }

    private void save(String fileName, String content) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
            bw.write(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getIpInfoJson(Process process) {
        final ProcessNetworkInfo processNetworkInfo = ipMap.getOrDefault(process.getUuid(), new ProcessNetworkInfo(process.getUuid()));

        if (processInjection.attacker2VictimThreads.containsKey(process)) {
            Set<etwThread> victimThreads = processInjection.attacker2VictimThreads.get(process);
            victimThreads.forEach(t -> {
                ProcessNetworkInfo victimProcessNetworkInfo = ipMap.get(t.getProcess().getUuid());
                if (victimProcessNetworkInfo == null)
                    return;

                List<IPInfo> ipInfos = victimProcessNetworkInfo.getIpInfos();
                ipInfos.forEach(ipInfo -> {
                    if (!processNetworkInfo.existIp(ipInfo)) {
                        processNetworkInfo.addIp(ipInfo.getSourceIp(), ipInfo.getTimestap());
                    }
                });
            });
        }

        if (processNetworkInfo.isEmpty()) {
            logger.info(String.format("uuid %d not found in ipMap.", process.getUuid()));

            // getProcessNetworkInfo from file
            ProcessNetworkInfo processNetworkInfoTemp = getIpInfoFromFile(process);

            if (processNetworkInfoTemp != null && !processNetworkInfoTemp.isEmpty()) {
                processNetworkInfoTemp.getIpInfos().forEach(ipInfo -> {
                    if (!processNetworkInfo.existIp(ipInfo)) {
                        processNetworkInfo.addIp(ipInfo.getSourceIp(), ipInfo.getTimestap());
                    }
                });
            }

        }

        if (processNetworkInfo != null) {
            return processNetworkInfo.toJson();
        }

        return "";
    }

    private ProcessNetworkInfo getIpInfoFromFile(Process process) {
        // 判断
        String fileName = String.format("ipInfo/%s/%d", process.getClientId(), process.getUuid());
        File file = new File(fileName);
        if (!file.exists())
            return null;

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
            Object obj = ois.readObject();
            if (obj != null && obj instanceof ProcessNetworkInfo) {
                return (ProcessNetworkInfo) obj;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    class ReportInfo {
        ReportInfo(Integer sport, String daddr) {
            this.sport = sport;
            this.daddr = daddr;
            this.count = new AtomicLong(0);
        }

        Integer sport;
        String daddr;
        Long lastEventTime = 0L;
        AtomicLong count;

        /**
         * 记录每次事件的事件，如果上一次事件事件 距离现在大于一定时间则上报
         *
         * @param eventTime
         * @return
         */
        boolean needReport(Long eventTime) {
            eventTime = eventTime / 1000000;// 毫秒

            long now = System.currentTimeMillis();
            boolean needReport = now - lastEventTime > 300000;
            this.lastEventTime = eventTime;
            return needReport;
        }
    }

}
