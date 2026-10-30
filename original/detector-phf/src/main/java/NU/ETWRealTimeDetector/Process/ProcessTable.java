package NU.ETWRealTimeDetector.Process;

import NU.ETWRealTimeDetector.ExtraDetectionFactors.AutoRunInfo;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.NetworkActivity;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.ProcessInjection;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.VisibleWindow;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.SysConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class ProcessTable {
    private static final Logger logger = LoggerFactory.getLogger(ProcessTable.class);
    private static final Integer processRetentionTime = SysConfig.getInteger("ProcessRetentionTime", 30);
    private static Map<String, ProcessTable> clientId2Instance = new HashMap<>();
    private static ScheduledExecutorService pool = Executors.newScheduledThreadPool(1, new ThreadFactory() {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix = "ProcessCleaner";

        @Override
        public Thread newThread(Runnable r) {
            return new Thread(r, namePrefix + threadNumber.getAndIncrement());
        }
    });

    public static ProcessTable getInstance(String clientId) {
        ProcessTable processTable = clientId2Instance.get(clientId);
        if (processTable == null) {
            processTable = new ProcessTable(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, processTable);
        return processTable;
    }

    public static Map<String, ProcessTable> getAllInstance() {
        return clientId2Instance;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private String clientId;
    private String uuid;
    private String ip;
    private Long collectorStartTime;
    private ConcurrentHashMap<Integer, Process> uuid2Process = new ConcurrentHashMap<>();
    private ConcurrentHashMap<Integer, ConcurrentSkipListSet<Process>> processId2ProcessList = new ConcurrentHashMap<>();
    private Process rootProcess;
    // 保存InitSignal的处理时间,该时间是处理时间，不是InitSignal时间的时间
    private Long initTime = 0L;
    // client系统启动时间
    private Long deviceBootTime = 0L;

    // process time
    private Long initTime2 = 0L;

    private Long preLogTime = -1L;

    private boolean cleaned = true;

    ProcessTable(String clientId) {
        this.clientId = clientId;

        collectorStartTime = LocalDateTime.now().toEpochSecond(ZoneOffset.of("+8"));
        rootProcess = new Process(clientId, 0, true);
        rootProcess.setCollectorStartTime(collectorStartTime);
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(0, new ConcurrentSkipListSet<>());
        processId2ProcessList.put(0, processSet);
        processSet.add(rootProcess);
    }

    public static void shutdown() {
        pool.shutdown();
    }

    public void setUuid(String uuid) {
        if (this.uuid == null) {
            this.uuid = uuid;
        }
    }

    public void setIp(String ip) {
        if (this.ip == null) {
            this.ip = ip;
        }
    }

    public String getUuid() {
        return this.uuid;
    }

    public String getIp() {
        if (this.ip == null) {
            return "";
        }

        return this.ip;
    }

    // 判断进程是否存在，仅当ProcessDCStart时调用
    public Process isExist(int processId, String fileName) {
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        if (processSet == null || processSet.isEmpty()) {
            return null;
        }

        Optional<Process> result = processSet.stream()
                .filter(process -> process.getStartTime() >= 0
                        && process.getEndTime() == 0
                        && process.getFileName().contains(fileName))
                .findFirst();
        if (result.isPresent()) {
            return result.get();
        } else {
            return null;
        }
    }

    public void addProcessStart(int processId, long timestamp, String fileName, String commandLine, boolean isDCStart) {
        VisibleWindow visibleWindow = VisibleWindow.getInstance(clientId);
        AutoRunInfo autoRunInfo = AutoRunInfo.getInstance(clientId);

        logger.info("{} ProcessStart pid:{}, time:{}, file:{}", clientId, processId, timestamp, fileName);
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        processId2ProcessList.put(processId, processSet);

        boolean processAlreadyExist = false;
        for (Process process : processSet) {
            // collector 重启，处理ProcessDCStart事件时，如果Process已经存在，进行关联，关联的条件是 Pid相同 并且 fileName 相同
            if (isDCStart && process.getStartTime() >= 0 && process.getEndTime() == 0 && process.getFileName().contains(fileName)) {
                processAlreadyExist = true;
                continue;
            }

            if (process.getAnyMiddleTime() <= timestamp) {
                continue;
            }
            // ProcessStart 事件 晚到的情况，因为其他事件先到，会先创建一个Process，startTime为0
            if (!isDCStart && process.getStartTime() == 0) {
                process.setStartTime(timestamp);
                process.setFileName(fileName);
                processAlreadyExist = true;
                visibleWindow.newProcessStarted(process);
                autoRunInfo.detectAutoRunProcess(process);
            }
        }
        if (!processAlreadyExist) {
            logger.info("{} New Process On ProcessStart pid:{}, time:{}, file:{}", clientId, processId, timestamp, fileName);
            Process process = new Process(clientId, processId, commandLine);
            process.setStartTime(timestamp);
            process.setFileName(fileName);
            process.setCollectorStartTime(collectorStartTime);
            processSet.add(process);
            uuid2Process.put(process.getUuid(), process);

            removeProcessSetIfLarge3(processSet);
            visibleWindow.newProcessStarted(process);
        }
    }

    public void addImageLoad(int processId, long timestamp, String imageFileName) {
        logger.info("{} ImageLoad pid:{}, time:{}, file:{}", clientId, processId, timestamp, imageFileName);
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        processId2ProcessList.put(processId, processSet);

        boolean processAlreadyExist = false;
        for (Process process : processSet) {
            //if (process.getEndTime() >= timestamp || process.getEndTime() == 0) {
            if (process.getStartTime() <= timestamp && (process.getEndTime() >= timestamp || process.getEndTime() == 0)) {
                processAlreadyExist = true;
                process.setUpdateTime(timestamp);
                if (process.getProcessName().equals("uninitialized_process")) {
                    process.setProcessName(imageFileName);
                    process.ensureFileName();
                }
            }
        }
        if (!processAlreadyExist) {
            logger.info("{} New Process On ImageLoad pid:{}, time:{}, file:{}", clientId, processId, timestamp, imageFileName);
            Process process = new Process(clientId, processId, "");
            process.setProcessName(imageFileName);
            process.setAnyMiddleTime(timestamp);
            process.setUpdateTime(timestamp);
            process.setCollectorStartTime(collectorStartTime);
            processSet.add(process);
            uuid2Process.put(process.getUuid(), process);

            removeProcessSetIfLarge3(processSet);
        }

    }

    public void addProcessEnd(int processId, long timestamp, String fileName) {
        logger.info("{} ProcessEnd pid:{}, time:{}, file:{}", clientId, processId, timestamp, fileName);
        if (!processId2ProcessList.containsKey(processId)) {
            return;
        }
        SortedSet<Process> processSet = processId2ProcessList.get(processId);

        for (Process process : processSet) {
            if (process.getStartTime() <= timestamp && process.getEndTime() == 0 && fileName.equals(process.getFileName())) {
                process.setEndTime(timestamp);
                pool.schedule(new NeedRemoveProcess(clientId, processId, process.getUuid()), processRetentionTime, TimeUnit.MINUTES);
            }
        }
        removeProcessSetIfLarge3(processSet);
    }

    public Process getProcessByPidAndProcessNameOrCreateOneIfNotExist(int processId, String processName, long timestamp) {
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        processId2ProcessList.put(processId, processSet);
        Process result = null;
        boolean found = false;
        for (Process process : processSet) {
            //if (process.getEndTime() >= timestamp || process.getEndTime() == 0) {
            if (process.getStartTime() <= timestamp && (process.getEndTime() >= timestamp || process.getEndTime() == 0)) {
                result = process;
                found = true;
                process.setUpdateTime(timestamp);
            }
        }

        if (!found) {
            // 如果根据时间没有找到，则根据进程名称找
            for (Process process : processSet) {
                if (process.getStartTime() <= timestamp && process.getProcessName().equalsIgnoreCase(processName)) {
                    result = process;
                    found = true;
                    process.setUpdateTime(timestamp);
                }
            }
        }

        if (!found) {
            logger.info("{} New Process on getProcessOrCreateOneIfNotExist pid:{}, time:{}, file:{}", clientId, processId, timestamp);
            result = new Process(clientId, processId, "");
            result.setAnyMiddleTime(timestamp);
            result.setCollectorStartTime(collectorStartTime);
            result.setUpdateTime(timestamp);
            processSet.add(result);
            uuid2Process.put(result.getUuid(), result);

            removeProcessSetIfLarge3(processSet);
        }
        return result;

    }

    public Process getProcessOrCreateOneIfNotExist(int processId, long timestamp) {
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        processId2ProcessList.put(processId, processSet);
        Process result = null;
        boolean found = false;
        for (Process process : processSet) {
            //if (process.getEndTime() >= timestamp || process.getEndTime() == 0) {
            if (process.getStartTime() <= timestamp && (process.getEndTime() >= timestamp || process.getEndTime() == 0)) {
                result = process;
                found = true;
                process.setUpdateTime(timestamp);
            }
        }
        if (!found) {
            logger.info("{} New Process on getProcessOrCreateOneIfNotExist pid:{}, time:{}, file:{}", clientId, processId, timestamp);
            result = new Process(clientId, processId, "");
            result.setAnyMiddleTime(timestamp);
            result.setCollectorStartTime(collectorStartTime);
            result.setUpdateTime(timestamp);
            processSet.add(result);
            uuid2Process.put(result.getUuid(), result);

            removeProcessSetIfLarge3(processSet);
        }
        return result;
    }

    public Process getProcess(int processId, long timestamp) {
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.get(processId);
        if (processSet == null)
            return null;
        for (Process process : processSet) {
            if (process.getStartTime() <= timestamp && (process.getEndTime() >= timestamp || process.getEndTime() == 0)) {
                return process;
            }
        }
        return null;
    }

    private void removeProcessSetIfLarge3(SortedSet<Process> processSet) {
        // keep the list size being small
        int needRemoveLength = processSet.size() - 3;
        if (needRemoveLength < 1) {
            return;
        }
        for (int i = 0; i < needRemoveLength; i++) {
            Process needRemoveProcess = processSet.first();
            uuid2Process.remove(needRemoveProcess.getUuid());
            processSet.remove(needRemoveProcess);
            removeProcess(needRemoveProcess);
            if (uuid2Process.size() > 0 && uuid2Process.size() % 100 == 0) {
                logger.warn("uuid2process Size:" + uuid2Process.size());
            }
        }
    }

    private void removeProcess(Process needRemoveProcess) {
        NetworkActivity.getInstance(clientId).removeProcessIpInfo(needRemoveProcess);
        DetectionFramework.getInstance(clientId).removeProcessNode(needRemoveProcess.getUuid());
    }

    public Process getCurrentAliveProcess(int processId) {
        Process result = null;
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());
        for (Process process : processSet) {
            if (process.getStartTime() != 0 && process.getEndTime() == 0) {
                result = process;
            }
        }
        return result;
    }

    public List<Process> getCurrentAliveProcessList(int processId) {
        return processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>())
                .stream()
                .filter(p -> p.getStartTime() != 0 && p.getEndTime() == 0)
                .collect(Collectors.toList());
    }

    public Process getMostRecentProcess(int processId) {
        ConcurrentSkipListSet<Process> processSet = processId2ProcessList.getOrDefault(processId, new ConcurrentSkipListSet<>());

        if (processSet.size() > 0) {
            return processSet.last();
        }
        return null;
    }

    public Process getProcessByUuid(int uuid) {
        Process result = uuid2Process.get(uuid);
        if (result == null) {
            result = new Process(clientId, 0, "");
            result.setCollectorStartTime(collectorStartTime);
            uuid2Process.put(result.getUuid(), result);
        }
        return result;
    }

    public Map<Integer, Process> getUuid2Process() {
        return uuid2Process;
    }

    public ConcurrentHashMap<Integer, ConcurrentSkipListSet<Process>> getProcessId2ProcessList() {
        return processId2ProcessList;
    }

    public static void removeProcess(String clientId, int uuid) {

        ProcessTable processTable = ProcessTable.getInstance(clientId);
        if (!processTable.uuid2Process.containsKey(uuid)) {
            return;
        }

        Process process = processTable.uuid2Process.get(uuid);
        if (process == null)
            return;

        // 判断是否为注入进程，如果是注入进程则不移除，等ProcessInjection发起移除
        ProcessInjection processInjection = ProcessInjection.getInstance(clientId);
        if (processInjection.possibleAttacker2VictimThreads.containsKey(process)
                || processInjection.attacker2VictimThreads.containsKey(process)) {
            return;
        }

        // remove network
        NetworkActivity.getInstance(clientId).removeProcessIpInfo(process);

        // remove process
        processTable.uuid2Process.remove(uuid);
        ConcurrentSkipListSet<Process> processSet = processTable.processId2ProcessList.get(process.getProcessId());
        if (processSet != null && !processSet.isEmpty()) {
            Optional<Process> needRemoveProcess = processSet.stream().filter(p -> p.getUuid() == uuid).findFirst();
            if (needRemoveProcess.isPresent()) {
                processSet.remove(needRemoveProcess.get());
                if (processSet.isEmpty()) {
                    processTable.processId2ProcessList.remove(process.getProcessId());
                }
            }
        }

        // 移除Framework中的ProcessNode
        DetectionFramework.getInstance(clientId).removeProcessNode(uuid);
    }

    public Long getCollectorStartTime() {
        return collectorStartTime;
    }

    public Process getRootProcess() {
        return rootProcess;
    }

    public void setInitTime(long time) {
        this.initTime = time;
        this.cleaned = false;
    }

    public void setInitTime2() {
        this.initTime2 = System.currentTimeMillis() / 1000;
    }

    public Long getInitTime2() {
        return this.initTime2;
    }

    public Long getPreLogTime() {   //yhs
        if(preLogTime == -1)
        {
            preLogTime = System.currentTimeMillis();
        }
        return preLogTime;
    }

    public void setPreLogTime(Long preLogTime) {
        this.preLogTime = preLogTime;
    }

    public void setDeviceBootTime(long time) {
        this.deviceBootTime = time;
    }

    public long getDeviceBootTime() {
        return deviceBootTime;
    }

    public long getInitTime() {
        return this.initTime;
    }

    public boolean getCleanedFlag() {
        return this.cleaned;
    }

    public void setCleaned() {
        this.cleaned = true;
    }

    //InitSignal 执行后60s执行清理操作，依赖60s 后的 第一条 ProcessStart 事件，遍历Process判断updateTime小于initTime的为 collector重启期间 已结束的进程，执行清理凑走
    public void clean() {
        List<Integer> needRemoveProcess = uuid2Process.values()
                .stream()
                .filter(p -> p.getUpdateTime() < initTime)
                .map(p -> p.getUuid())
                .collect(Collectors.toList());

        needRemoveProcess.forEach(uuid -> {
            logger.info("Process clean after collector restart: " + uuid);
            removeProcess(this.clientId, uuid);
        });
        cleaned = true;
    }

    private static class NeedRemoveProcess implements Runnable {

        private final String clientId;
        private final Integer processId;
        private final Integer uuid;

        NeedRemoveProcess(String clientId, Integer processId, Integer uuid) {
            this.clientId = clientId;
            this.processId = processId;
            this.uuid = uuid;
        }

        @Override
        public void run() {
            removeProcess(clientId, uuid);
        }
    }


}
