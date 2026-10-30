package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.ETWproto.Etwdata;
import NU.ETWRealTimeDetector.ETWproto.Etwdata.EventRecords;
import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventFormat;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.EventRecord.ReceivedMessage;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.*;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Event.NetworkEventForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.FileNodeV2;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.IPC.HealthCheckReporter;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Pojo.IpRangeInfo;
import NU.ETWRealTimeDetector.Pojo.SensitiveProgram2Info;
import NU.ETWRealTimeDetector.Pojo.etwThread;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DeduplicatingEvent;
import NU.ETWRealTimeDetector.Util.FileOperation;
import NU.ETWRealTimeDetector.Util.NetworkOperation;
import NU.ETWRealTimeDetector.Util.snapshot.ProcessInfo;
import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;
import NU.ETWRealTimeDetector.Util.snapshot.ThreadInfo;
import com.google.gson.Gson;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xerial.snappy.Snappy;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class MessageProcessor extends Thread {
    private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int moduleSwitch = SysConfig.getInteger("Switch", 10);
    private static final boolean dumpSnapshot = SysConfig.getBoolean("DumpSnapshot", false);
    private static final Logger logger = LoggerFactory.getLogger(MessageProcessor.class);
    private static final Logger powershellLogger = LoggerFactory.getLogger("powershell");
    private static Logger ssLogger = LoggerFactory.getLogger("snapshot");
    private static Logger certLogger = LoggerFactory.getLogger("certificate");
    private LinkedBlockingQueue<ReceivedMessage> upstream;
    private StringBuilder builder = new StringBuilder();
    private static StringBuilder ouputBuilder = new StringBuilder();
    public static ConcurrentHashMap<String, Integer> honyPotList = new ConcurrentHashMap<>();
    public static Set<Integer> portList = new HashSet<>();
    public static Set<IpRangeInfo> excludeExternalIpList = new HashSet<>();
    public static Set<IpRangeInfo> excludeInternalIpList = new HashSet<>();
    public static boolean intranet_mode = true;
    public static Set<Integer> whiteAppList = new HashSet<>();
    private Gson gson = new Gson();
    private AtomicLong currentTime;
    private AtomicLong currentTotalCallstack;   //yhs
    private AtomicLong currentTotalCallstackSize;
    private AtomicLong currentTotalSize;
    private AtomicLong currentTotalEvent;   //have used
    private AtomicLong TotalCPUTime;
    private AtomicLong TotalCallstackCPUTime;

    private AtomicLong currentTotalEventFromInitSignal;
    private AtomicLong currentTotalPacket;
    private AtomicLong currentDuplicateEvent;

    private DeduplicatingEvent currentDeduplicatingEvent;
    private String currentClientId;
    private String currentUuid;
    private DetectionFramework currentFramework;
    private ProcessTable currentProcessTable;
    private Certificate currentCertificate;
    private Macro currentMacro;
    private NetworkActivity currentNetworkActivity;
    private PowerShell currentPowerShell;
    private ProcessInjection currentProcessInjection;
    private SensitiveFile currentSensitiveFile;
    private SensitiveProgram currentSensitiveProgram;
    private SensitiveProgram2 currentSensitiveProgram2;
    private VisibleWindow currentVisibleWindow;
    private FileFromUDisk currentFileFromUDisk;
    private AutoRunInfo currentAutoRunInfo;
    private Cryptomining currentCryptoMining;
    private HoneyPot currentHoneyPot;
    private EventRecord currentPreviousRecord;
    private ThreatIntelligence currentThreatIntelligence;
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);
    private static final String excludeExtensionOfDownloadFile = SysConfig.getString("ExcludeExtensionOfDownloadFile", "");

    public MessageProcessor(LinkedBlockingQueue<ReceivedMessage> upstream) {
        this.upstream = upstream;
    }

    /*
     * check data count, if wrong, shutdown; if correct, return a List of
     * EtwEventType
     * If format error, return null
     */
    private List<EtwEventType> preCheck(EventRecords eventRecords) {
        int eventRecordSize = eventRecords.getProcessIDCount();
        Map<EtwEventType, Integer> eventType2Count = new HashMap<>();
        List<EtwEventType> etwEventTypeList = new ArrayList<>(eventRecordSize);
        int dataIndex = 0;
        for (int i = 0; i < eventRecordSize; i++) {
            long providerId = eventRecords.getProviderID(i);
            int opcode = eventRecords.getOpcode(i);
            long eventKey = providerId + opcode * 31;
            EtwEventType etwEventType = EventFormat.getEventTypeUsingEventKey(eventKey);
            etwEventTypeList.add(etwEventType);

            if (EtwEventType.Unknown.equals(etwEventType)) {
                logger.error("unknown event, providerId: {}, opcode: {}", providerId, opcode);
            }

            if (eventType2Count.containsKey(etwEventType)) {
                eventType2Count.put(etwEventType, eventType2Count.get(etwEventType) + 1);
            } else {
                eventType2Count.put(etwEventType, 1);
            }
            Integer lengthOfThis = EventFormat.getArgSizeUsingEventType(etwEventType);
            dataIndex += lengthOfThis;
        }

        if (dataIndex != eventRecords.getDataCount()) {
            try (BufferedWriter bw = new BufferedWriter(new FileWriter("error_report.txt"))) {
                logger.error("format error");
                bw.write("format: " + dataIndex + " real: " + eventRecords.getDataCount() + "\n");
                for (Map.Entry<EtwEventType, Integer> entry : eventType2Count.entrySet()) {
                    bw.write(entry.toString());
                    bw.newLine();
                }
                bw.close();
                return null;
            } catch (Exception e) {
                logger.error("buffered writer error", e);
            }
        }
        return etwEventTypeList;
    }

    private void constructEventRecord(EventRecords eventRecords, List<EtwEventType> etwEventTypeList, String clientId) {
        int eventRecordsSize = etwEventTypeList.size();
        int dataIndex = 0;
        int callstackIndex = 0;
        for (int i = 0; i < eventRecordsSize; i++) {
            EtwEventType etwEventType = etwEventTypeList.get(i);
            int processId = eventRecords.getProcessID(i);
            int threadId = eventRecords.getThreadID(i);
            long timestamp = eventRecords.getTimestamp(i);
            EventRecord record = new EventRecord(etwEventType, processId, threadId, timestamp);
            List<String> argNames = EventFormat.getArgNamesUsingEventType(etwEventType);
            int argSize = EventFormat.getArgSizeUsingEventType(etwEventType);
            for (int j = 0; j < argSize; j++) {
                Etwdata.datad data = eventRecords.getData(dataIndex + j);
                if (data.getSCount() != 0) {
                    record.argument.put(argNames.get(j), data.getS(0).toStringUtf8());
                } else {
                    record.argument.put(argNames.get(j), data.getD(0));
                }
            }
            dataIndex += argSize;
            if (etwEventType == EtwEventType.Callstack) {
                record.setCallstack(eventRecords.getCallstack(callstackIndex++).toStringUtf8());
            }

            currentTotalEvent.incrementAndGet();
            currentTotalEventFromInitSignal.incrementAndGet();

            if (moduleSwitch <= 2) {
                return;
            }
            // deduplicate
            if (exist(record)) {
                currentDuplicateEvent.incrementAndGet();
                continue;
            }

            if (moduleSwitch <= 3) {
                return;
            }

            if (!record.duplicatesWith(currentPreviousRecord)) {
                currentTotalSize.addAndGet(record.toString().length());
                distributeRecord(record);
                currentPreviousRecord = record;
            }
        }
    }

    public boolean exist(EventRecord record) {
        builder.delete(0, builder.length());

        Process process;

        switch (record.getEtwEventType()) {
            case UdpIpRecvIPV4:
            case UdpIpSendIPV4:
            case TcpIpRecvIPV4:
            case TcpIpSendIPV4:
            case TcpIpDisconnectIPV4:
            case TcpIpConnectIPV4:
                if (!record.argument.containsKey("daddr")) {
                    return true;
                }
                builder.append(record.getProcessId());
                builder.append(record.argument.get("daddr"));
                builder.append(record.argument.get("dport"));

                int processId = record.getProcessId();
                long timestamp = record.getTimestamp();

                process = currentProcessTable.getProcess(processId, timestamp);
                if (process != null) {
                    process.setLastNetworkTimestamp(timestamp);
                }
                return currentDeduplicatingEvent.exist(builder);
            case DNSQueryRequest:
                if (!record.argument.containsKey("QueryDomainName")) {
                    return true;
                }
                builder.append(record.getProcessId());
                builder.append(record.argument.get("QueryDomainName"));
                return currentDeduplicatingEvent.exist(builder);
            case FileIoRead:
            case FileIoWrite:
                if (!record.argument.containsKey("FileName")) {
                    return true;
                }
                builder.append(record.getProcessId());
                builder.append(record.getEtwEventType());
                builder.append(record.argument.get("FileName"));
                return currentDeduplicatingEvent.exist(builder);
            case Callstack:
                builder.append(record.getProcessId());
                builder.append(record.getEtwEventType());
                builder.append(record.getCallstack());
                builder.append(record.getThreadId());
                boolean exists = currentDeduplicatingEvent.exist(builder);
                if (exists) {
                    // double check
                    process = currentProcessTable.getProcess(record.getProcessId(), record.timestamp);
                    if (process == null) {
                        return false;
                    }

                    if (!currentFramework.getProcessMap().containsKey(process.getUuid())) {
                        return false;
                    }

                    LabelType labelType = null;
                    switch (record.callstack) {
                        case "AudioRecord":
                            labelType = LabelType.PT5;
                            break;
                        case "Keylogger":
                        case "KeyloggerBackground":
                            labelType = LabelType.PT7;
                            break;
                        case "RemoteDesktop":
                            labelType = LabelType.PT8;
                            break;
                        case "RemoteShell":
                            labelType = LabelType.PT9;
                            break;
                        case "ScreenGrab":
                            labelType = LabelType.PT16;
                            break;
                        case "ReflectiveLoading":
                            labelType = LabelType.PT11;
                            break;
                        default:
                            break;
                    }

                    if (labelType == null) {
                        return exists;
                    }

                    ProcessNode processNode = currentFramework.getProcessMap().get(process.getUuid());

                    if (!processNode.existLabel(labelType)) {
                        return false;
                    }

                }

                return exists;
        }

        return false;
    }

    public void distributeRecord(EventRecord record) {
        long timeNow = System.currentTimeMillis();
        switch (record.getEtwEventType()) {
            case Callstack: {
                currentTotalCallstack.incrementAndGet();
                processCallstack(record);
                break;
            }
            case VisibleWindowInfo:
                processVisibleWindow(record);
                break;
            case FileIoRead:
                processFileIoRead(record);
                break;
            case FileIoWrite:
                processFileIoWrite(record);
                break;
            case FileIoRename:
                processFileIoRename(record);
                break;
            case FileIoCreate:
                processFileIoCreate(record);
                break;
            case ImageLoad:
                processImageLoad(record);
                break;
            case ImageDCStart:
                processImageLoad(record);
                break;
            case ProcessStart:
                processProcessStart(record);
                break;
            case ProcessDCStart:
                processProcessStart(record);
                break;
            case ProcessEnd:
                processProcessEnd(record);
                break;
            case ThreadEnd:
                processThreadEnd(record);
                break;
            case ThreadStart:
                processThreadStart(record);
                break;
            case ThreadDCStart:
                processThreadStart(record);
                break;
            case TcpIpConnectIPV4:
                processNetworkConnect(record);
                break;
            case TcpIpDisconnectIPV4:
                processNetworkClose(record);
                break;
            case TcpIpSendIPV4:
                processNetworkSend(record);
                break;
            case TcpIpRecvIPV4:
                processNetworkRecv(record);
                break;
            case TcpIpAcceptIPV4:
                processTcpIpAcceptIPV4(record);
                break;
            case UdpIpSendIPV4:
                processNetworkSend(record);
                break;
            case UdpIpRecvIPV4:
                processNetworkRecv(record);
                break;
            case PowerShellCheck:
                processPowerShell(record);
                break;
            case FileMacroCheck:
                processMacro(record);
                break;
            case FileIoFileCreate:
                processFileIoFileCreate(record);
                break;
            case DeviceRemoveAble:
                processDeviceRemovable(record);
                break;
            case FileIoDelete:
                processFileIoDelete(record);
                break;
            case HealthCheck:
                processHealthCheck(record);
                break;
            case InitSignal:
                processInitSignal(record);
                break;
            case AutorunInfo:
                processAutorunInfo(record);
                break;
            case DNSQueryRequest:
                processDNSQueryRequest(record);
                break;
            case DNSQueryResult:
                break;
            case RansomCheck:
                processRansomCheck(record);
                break;
            case EVTSecurity:
                processEVTSecurity(record);
                break;
            case ZoneIdentifier:
                processZoneIdentifier(record);
                break;
            case RuleIdentifier:
                processRuleIdentifier(record);
                break;
            case HashInfo:
                processHashInfo(record);
                break;
            case ProcessAccess:
                processProcessAccess(record);
                break;
            case PowershellResult:
                processPowerShellResult(record);
                break;
            default:
                break;
        }
        TotalCPUTime.addAndGet(System.currentTimeMillis() - timeNow);
    }

    private void processPowerShellResult(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();

        Map<String, Object> argument = record.getArgument();
        // 分数  score<4 Low Risk    6>score>=4 Mild Risk  6<=score<=10 Moderate Risk 10<score<=20 Elevated Risk score>20 Severe Risk
        Long score = (Long) argument.getOrDefault("MacroResult", 0L);

        powershellLogger.info("pid:{} timestamp:{} {}", processId, timestamp, argument);
        if (score <= 5) {
            return;
        }

        // 行为
        String signature = argument.get("ExtraInfo").toString();

        // powershell内容
        String powershell = argument.get("CommandLine").toString();

        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);

        String networkInfoJson = NetworkActivity.getInstance(this.currentClientId).getIpInfoJson(process);
        Map<String, Object> args = new HashMap<>();
        args.put("score", score.intValue());
        args.put("powershell_script", powershell);

        String labels = getPowershellLabel(signature);
        String eventId = UUID.randomUUID().toString();
        Reporter.reportResult(process.getClientId(), process, labels, "Powershell", networkInfoJson, args, eventId);
        Neo4jClient.getInstance().drawAttackGraph(currentClientId, process, eventId);
        Neo4jClient.getInstance().drawProcessRelationGraph(currentClientId, process, eventId);

        /**
         *
         "Code Injection", 10.0
         "Key Logging", 3.0
         "Screen Scraping", 2.0
         "AppLocker Bypass", 2.0
         "AMSI Bypass", 2.0
         "Clear Logs", 2.0
         "Coin Miner", 6.0
         "Embedded File", 4.0
         "Abnormal Size", 2.0
         "Ransomware", 10.0
         "DNS C2", 2.0
         "Disabled Protections", 4.0
         "Negative Context", 10.0
         "Malicious Behavior Combo", 6.0
         "Known Malware", 10.0
         */

        // Neutral
        // Behaviors which require more context to infer intent.

        /*
         "Downloader", 1.5
         "Starts Process", 1.5
         "Script Execution", 1.5
         "Compression", 1.5
         "Hidden Window", 0.5
         "Custom Web Fields", 1.0
         "Persistence", 1.0
         "Sleeps", 0.5
         "Uninstalls Apps", 0.5
         "Obfuscation", 1.0
         "Crypto", 2.0
         "Enumeration", 0.5
         "Registry", 0.5
         "Sends Data", 1.0
         "Byte Usage", 1.0
         "SysInternals", 1.5
         "One Liner", 2.0
         "Variable Extension", 2.0
         */

        // Benign
        // Behaviors which are generally only seen in Benign scripts - subtracts from score.
        /*
        "Script Logging", -1.0
        "License", -2.0
        "Function Body", -2.0
        "Positive Context", -3.0
         */

    }

    public static String getPowershellLabel(String signature) {
        String label = signature.replace("[", "")
                .replace("]", "");


        List<String> list = Arrays.stream(label.split(","))
                .map(s -> s.split("-")[0])
                .map(s -> s.split(":")[0])
                .map(s -> s.replace(" ", ""))
                .collect(Collectors.toList());

        return String.join(",", list);
    }

    private void processHashInfo(EventRecord record) {
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int processId = (int) (long) argument.get("ProcessId");
        String fileName = argument.get("FileName").toString();
        String md5 = argument.get("MD5").toString();
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        process.setMd5(md5);
        ProcessNode node = currentFramework.getProcessNode(process.getUuid());
        if (node == null) {
            return;
        }
        Neo4jClient.getInstance().addProperty(node, "md5", md5);
        // 如果该进程是恶意进程则 刷新画图
        currentFramework.findAttackerAndDrawGraph(node);
    }

    private void processProcessAccess(EventRecord record) {
        // processId 注入进程pid
        // argument.ProcessId 被注入进程pid
        // argument.ProcessName 被注入进程名
        // argument.ParentId 注入进程Pid
        // argument.ParentProcessName 注入进程名

        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();

        int processId = record.getProcessId();
        int victimProcessId = (int) (long) argument.get("ProcessId");
        String parentProcessName = argument.get("ParentProcessName").toString();
        Process process = currentProcessTable.getProcessByPidAndProcessNameOrCreateOneIfNotExist(processId, parentProcessName, timestamp);
        //currentProcessInjection.addProcessAccess(process, timestamp);

        // 如果被注入进程是lsass.exe,给注入进程打上PT42标签
        String processName = argument.get("ProcessName").toString();
        if ((process.getFileName().equalsIgnoreCase("mimikatz.exe") || process.getFileName().equalsIgnoreCase("powershell.exe") || process.getFileName().equalsIgnoreCase("rundll32.exe")) && processName.toLowerCase().endsWith("lsass.exe")) {
            LabelForCS label = new LabelForCS(LabelType.PT42, currentClientId, process.getUuid(), timestamp, "");
            currentFramework.addLabel(label);
        }
    }

    private void processRuleIdentifier(EventRecord record) {
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int ruleId = (int) (long) argument.get("RuleId");
        String eventName = argument.get("EventName").toString();
        String params = argument.get("CommandLine").toString();
        RuleMatch.getInstance(currentClientId).processSimpleRuleEvent(ruleId, eventName, params, timestamp);
    }


    private void processZoneIdentifier(EventRecord record) {
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int processId = (int) (long) argument.get("ProcessId");
        int zoneId = (int) (long) argument.get("ZoneId");
        String referrerUrl = argument.get("ReferrerUrl").toString();
        String hostUrl = argument.get("HostUrl").toString();
        String fileName = argument.get("FileName").toString().toLowerCase();

        logger.info("ZoneIdentifier clientId:{} processId:{} zoneId:{} referrerUrl:{} hostUrl:{} fileName:{}", currentClientId, processId, zoneId, referrerUrl, hostUrl, fileName);

        // 判断文件是否包含 FT6 从网络下载的标签
        // 如果不包含则 记录下载的URL，zoneId 到FileNode
        //             给文件打 标签 通过浏览器下载
        // 判断进程名称是否跟文件名称一致，如果一致则说明是 Load_OWN_EXE，如果没有PT22，则打上PT22标签

        FileNodeV2 fileNode = currentFramework.getFileNodeV2(fileName);

        boolean existLabel = fileNode != null && fileNode.existLabel(LabelType.FT6);

        if (existLabel) {
            return;
        }

        // 记录URL
        Neo4jClient.getInstance().addZoneIdentifier(currentClientId, fileNode.getUuid(), zoneId, referrerUrl, hostUrl, fileName);

        // Add label FT6
        LabelForCS label = new LabelForCS(LabelType.FT6, currentClientId, timestamp, fileName);
        currentFramework.addLabel(label);

        // Add label PT22
        Process process = currentProcessTable.getProcess(processId, timestamp);
        if (process == null) {
            return;
        }

        ProcessNode processNode = currentFramework.getProcessNode(process.getUuid());
        if (processNode == null) {
            return;
        }

        existLabel = processNode.getLabels().contains(LabelType.PT22);
        if (!existLabel) {
            currentFramework.addEvent(new EventForCS(EventType.Zone_Identifier, currentClientId, process, timestamp, fileName, ""));
        }


    }

    private void processTcpIpAcceptIPV4(EventRecord record) {

        // 判断当前client是不是蜜罐
        // 如果是蜜罐则进行端口判断

        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        Map<String, Object> argument = record.getArgument();
        int sourcePort = (int) (long) argument.get("sport");
        int destinationPort = (int) (long) argument.get("dport");
        Long sourceIpAddress = Long.valueOf(argument.get("saddr").toString());
        Long destinationIpAddress = Long.valueOf(argument.get("daddr").toString());

        if (honyPotList.containsKey(currentClientId)) {
            currentNetworkActivity.reportPortAccessed(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, "tcp");
        }

        // 产生这个事件说明这个进程 监听了端口，暴露了服务，因此可能存在漏洞，会被攻击者利用
        // 排除 localhost
        if (!sourceIpAddress.equals(16777343L) && !destinationIpAddress.equals(16777343L)) {
            LabelForCS label = new LabelForCS(LabelType.PT105, currentClientId, process.getUuid(), timestamp, "");
            currentFramework.addLabel(label);
        }

    }

    private void processEVTSecurity(EventRecord record) {
        long timestamp = record.getTimestamp();
        if (record.argument.containsKey("CommandLine")) {
            String commandline = record.argument.get("CommandLine").toString();
            logger.info("EVTSecurity argument CommandLine:{}", commandline);
            //"{\"EventID\":4624,\"ProcessId\":552,\"ThreadId\":656,\"SystemTime\":\"2020-04-13T01:29:15.632093000Z\",\"SubjectUserName\":\"WSF-POC-CLIENT$\",\"SubjectDomainName\":\"WORKGROUP\",\"TargetUserName\":\"SYSTEM\",\"TargetDomainName\":\"NT AUTHORITY\",\"LogonType\":5,\"WorkstationName\":\"\",\"IpAddress\":\"-\",\"IpPort\":\"-\"}"
            if (honyPotList.containsKey(currentClientId)) {
                // 蜜罐检测
                // 检测到 EventID 4624 登录 4625 登录失败 4634 注销 上报
                if (commandline.contains("\"EventID\":4624")) {// 登录成功
                    currentHoneyPot.reportUserLogonSuccess(commandline, timestamp);
                } else if (commandline.contains("\"EventID\":4625")) {// 登录失败
                    currentHoneyPot.reportUserLogonFailed(commandline, timestamp);
                } else if (commandline.contains("\"EventID\":4634")) {// 注销
                    currentHoneyPot.reportUserLogonOff(commandline, timestamp);
                } else if (commandline.contains("\"EventID\":4720")) {// 创建用户
                    currentHoneyPot.reportCreateUser(commandline, timestamp);
                } else if (commandline.contains("\"EventID\":4726")) {// 删除用户
                    currentHoneyPot.reportDeleteUser(commandline, timestamp);
                } else if (commandline.contains("\"EventID\":4723") || commandline.contains("\"EventID\":4724")) {// 4723 修改自己账户密码 4724 修改别人账户密码
                    currentHoneyPot.reportChangeUserPassword(commandline, timestamp);
                }
            }
        }
    }

    private void processRansomCheck(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();

        Map<String, Object> argument = record.getArgument();
        int ppid = (int) (long) argument.get("ParentId");
        String processName = String.valueOf(argument.get("ProcessName"));
        String parentProcessName = String.valueOf(argument.get("FileName"));
        String extraInfo = String.valueOf(argument.get("ExtraInfo"));

        Ransomware.reportRansomware(currentClientId, processId, ppid, processName, parentProcessName, extraInfo, timestamp);
    }

    private void processDNSQueryRequest(EventRecord record) {
        if (!record.argument.containsKey("QueryDomainName")) {
            return;
        }
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        String dns = record.argument.get("QueryDomainName").toString();
        currentCryptoMining.checkDNS(process, dns, timestamp);
    }


    public void setCurrent(String clientID) {
        currentClientId = clientID;
        currentFramework = DetectionFramework.getInstance(clientID);
        currentProcessTable = ProcessTable.getInstance(clientID);
        currentCertificate = Certificate.getInstance(clientID);
        currentMacro = Macro.getInstance(clientID);
        currentNetworkActivity = NetworkActivity.getInstance(clientID);
        currentPowerShell = PowerShell.getInstance(clientID);
        currentProcessInjection = ProcessInjection.getInstance(clientID);
        currentSensitiveFile = SensitiveFile.getInstance(clientID);
        currentSensitiveProgram = SensitiveProgram.getInstance(clientID);
        currentSensitiveProgram2 = SensitiveProgram2.getInstance(clientID);
        currentVisibleWindow = VisibleWindow.getInstance(clientID);
        currentFileFromUDisk = FileFromUDisk.getInstance(clientID);
        currentAutoRunInfo = AutoRunInfo.getInstance(clientID);
        currentCryptoMining = Cryptomining.getInstance(clientID);
        currentHoneyPot = HoneyPot.getInstance(clientID);
        currentThreatIntelligence = ThreatIntelligence.getInstance(clientID);
        currentPreviousRecord = null;

        currentTime = CountingEvent.getCounter(clientID, "currentTime");
        currentTotalEvent = CountingEvent.getCounter(clientID, "TotalEvent");
        currentTotalCallstack = CountingEvent.getCounter(clientID, "TotalCallstack");
        currentTotalSize = CountingEvent.getCounter(clientID, "TotalSize");
        currentTotalCallstackSize = CountingEvent.getCounter(clientID, "TotalCallstackSize");
        TotalCPUTime = CountingEvent.getCounter(clientID, "TotalCPUTime");
        TotalCallstackCPUTime = CountingEvent.getCounter(clientID, "TotalCallstackCPUTime");


        currentTotalEventFromInitSignal = CountingEvent.getCounter(clientID, "TotalEventFromInitSignal");
        currentTotalPacket = CountingEvent.getCounter(clientID, "TotalPacket");
        currentDuplicateEvent = CountingEvent.getCounter(clientID, "TotalDuplicateEvent");
        currentDeduplicatingEvent = DeduplicatingEvent.getInstance(clientID);

    }

    @Override
    public void run() {
        while (true) {
            try {
                ReceivedMessage receivedMessage = upstream.take();
                process(receivedMessage);
            } catch (Exception e) {
                logger.error("interrupted", e);
            }
        }
    }

    public void process(ReceivedMessage receivedMessage) {  //main logic of the process,yhs annotation
        EventRecords eventRecords;
        String clientId = receivedMessage.getClientID();
        String uuid = receivedMessage.getUuid();
        String ip = receivedMessage.getIp();

        try {
            // uncompress
            byte[] uncompressedMessage = Snappy.uncompress(receivedMessage.getValue());
            // deserialize
            eventRecords = EventRecords.parseFrom(uncompressedMessage);
            setCurrent(clientId);
            currentProcessTable.setUuid(uuid);
            currentProcessTable.setIp(ip);
            currentTotalPacket.incrementAndGet();
            if (currentTotalPacket.get() % 500 == 0) {
                outputEventCount(clientId, currentTotalEvent, currentTotalEventFromInitSignal, currentTotalPacket, currentDuplicateEvent, false);
                outputCallstackCount(clientId, currentTotalEvent, currentTotalPacket, currentDuplicateEvent, currentTotalCallstack,currentTotalSize,currentTotalCallstackSize, TotalCPUTime,TotalCallstackCPUTime, currentTime);
            }
            List<EtwEventType> etwEventTypeList = preCheck(eventRecords);
            if (etwEventTypeList != null) {
                constructEventRecord(eventRecords, etwEventTypeList, clientId);
            } else {
                logger.error("format error in client {}", clientId);
            }
        } catch (Exception e) {
            logger.error(String.format("process error %s.", clientId), e);
        }
    }

    private void processCallstack(EventRecord record) {
        currentTotalCallstackSize.addAndGet(record.toString().length());
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        long t_1 = timestamp / 1000000;
        Date Datea = new Date(t_1);
        int threadId = record.getThreadId();
        String callStackIndexStr = record.getCallstack();
        //start the process
        long timeNow = System.currentTimeMillis();
        final int feature_num = CallstackProcessor.getFeatureNum();
        double[] weights = new double[feature_num];
        String[] w = callStackIndexStr.split(",");
        for (String weight : w) {
            String[] info = weight.split("_");
            if (info.length == 2) {
                try {
                    int index = Integer.parseInt(info[0]);
                    double proportion = Double.parseDouble(info[1]);
                    if (index < feature_num && index >= 0 && proportion>=0 && proportion <= 1) {
                        weights[index] = proportion;
                    }
                } catch (NumberFormatException e) {
                    ;
                }
            }
        }
        //System.out.println("========> get the phf， pid: "+processId + ",tid: "+threadId+",timestamp: "+timestamp);

        String callStackStr = CallstackProcessor.preProcessCallstack(weights);  //get the tag
        TotalCallstackCPUTime.addAndGet(System.currentTimeMillis() - timeNow);
        if(callStackStr.length() == 0){
            return ;
        }
        //over
        double p = CallstackProcessor.getP();

        try (BufferedWriter pw = new BufferedWriter(new FileWriter("phflogger", true))) {
            pw.write("========> get the phf， time: " + timestamp + "( "+ Datea +" ) "+", result: {pid: "+processId + ",tag: "+ callStackStr+", p: "+p+" }");
            pw.newLine();
        }catch (Exception e)
        {
            logger.error("pw error", e);
        }
        //powershellLogger.info("==========> get the phf result: {pid: "+processId + ",tag: "+ callStackStr+", p: "+p+" }");
        callStackStr.replaceAll("ReverseShell","RemoteShell");
        List<String> callStacks = new ArrayList<>();
        if (callStackStr != null) {
            callStacks.addAll(Arrays.asList(callStackStr.split(",")));// 逗号间隔 例如：RemoteShell,ScreenGrab
        }
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);

        boolean isPossibleVictimThread = currentProcessInjection.isPossibleVictimThread(process, threadId);

        //process = currentProcessInjection.getRealProcess(process, record.getThreadId());

        /**
         *
         if (process.getFileName().toLowerCase().equals("winlogon.exe")) {// winlogon.exe 特殊处理，默认,检查winlogon 做了PHF 的线程是不是 spoolsv创建的线程
         etwThread etwThread = new etwThread(process, threadId);
         Map<etwThread, Process> possibleVictimThread2Attacker = currentProcessInjection.getPossibleVictimThread2Attacker();
         if (possibleVictimThread2Attacker.containsKey(etwThread)) {
         Process attacker = possibleVictimThread2Attacker.get(etwThread);
         if (attacker.getFileName().toLowerCase().equals("spoolsv.exe")) {
         process = attacker;
         }
         }
         }
         */

        boolean isVictimThread = currentProcessInjection.isVictimThread(process, record.getThreadId());

        if (TURN_ON_DUMP) {
            try (BufferedWriter pw = new BufferedWriter(new FileWriter("PhfReport.txt", true))) {
                pw.write(new Date(timestamp / 1000000) + " " + process + " " + callStackStr);
                pw.newLine();
            } catch (Exception e) {
                logger.error("pw error", e);
            }
        }

        for (String phf : callStacks) {
            LabelForCS label = null;
            if (!isVictimThread && !isPossibleVictimThread) {
                switch (phf) {
                    case "AudioRecord":
                        label = new LabelForCS(LabelType.PT5, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "KeyloggerBackground":
                    case "Keylogger":
                        label = new LabelForCS(LabelType.PT7, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "RemoteDesktop":
                        label = new LabelForCS(LabelType.PT8, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "RemoteShell":
                        label = new LabelForCS(LabelType.PT9, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ScreenGrab":
                        label = new LabelForCS(LabelType.PT16, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ReflectiveLoading":
                        label = new LabelForCS(LabelType.PT11, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ProcessInjection":
                        currentProcessInjection.addPossibleInjection(process, timestamp);
                        // 给注入进程打上PT40,注入者标签
                        currentProcessInjection.markInjecter(process, timestamp);
                        // 给被注入的进程打上PT41  为了能够在攻击图上将注入展示出来
                        currentProcessInjection.markVictimProcessBeInjected(process, timestamp);
                        break;
                    default:
                        break;
                }
            } else {
                switch (phf) {
                    case "AudioRecord":
                        label = new LabelForCS(LabelType.PT65, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "KeyloggerBackground":
                    case "Keylogger":
                        label = new LabelForCS(LabelType.PT67, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "RemoteDesktop":
                        label = new LabelForCS(LabelType.PT68, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "RemoteShell":
                        label = new LabelForCS(LabelType.PT69, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ScreenGrab":
                        label = new LabelForCS(LabelType.PT76, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ReflectiveLoading":
                        label = new LabelForCS(LabelType.PT11, currentClientId, process.getUuid(), timestamp, "");
                        break;
                    case "ProcessInjection":
                        currentProcessInjection.addPossibleInjection(process, timestamp);
                        // 给注入进程打上PT40,注入者标签
                        currentProcessInjection.markInjecter(process, timestamp);
                        // 给被注入的进程打上PT41  为了能够在攻击图上将注入展示出来
                        currentProcessInjection.markVictimProcessBeInjected(process, timestamp);
                        break;
                    default:
                        break;
                }

            }

            if (isPossibleVictimThread && !isVictimThread && !phf.equals("ProcessInjection") && !phf.equals("ReflectiveLoading")) {
                currentProcessInjection.addPossibleVictimThreadPhfLabel(process, threadId, label);
                continue;
            }

            if (label != null) {
                currentFramework.addLabel(label);

                // 判断是否是远程线程执行了恶意行为
                /**
                 *
                 etwThread etwThread = new etwThread(process, threadId);
                 Map<etwThread, Process> victimThread2Attacker = currentProcessInjection.getPossibleVictimThread2Attacker();
                 if (victimThread2Attacker.containsKey(etwThread)) {
                 Process attacker = victimThread2Attacker.get(etwThread);
                 if (attacker != null) {
                 EventForCS remoteThreadPHFEvent = new EventForCS(EventType.REMOTE_THREAD_PHF, currentClientId, process, timestamp, attacker.getUuid(), "", "");
                 currentFramework.addEvent(remoteThreadPHFEvent);
                 }
                 }
                 */

                // 查询parentuuid，如果parent是cmd，则继续上一级,如果上一级是explorer.exe，则不产生事件
                if (phf.equals("ReflectiveLoading")) {
                    return;
                }

                if (isVictimThread) {
                    currentProcessInjection.triggerRemoteThreadPHFEvent(process, threadId, timestamp, label.getType());
                }
                /*
                ProcessNode processNode = currentFramework.getProcessNode(process.getUuid());
                if (processNode == null)
                    return;

                ProcessNode parentProcessNode = processNode.getParentNode();
                if (parentProcessNode == null || parentProcessNode.getProcess().getFileName().toLowerCase().contains("explorer")) {
                    return;
                }

                if (parentProcessNode.getProcess().getFileName().toLowerCase().contains("cmd")) {
                    parentProcessNode = parentProcessNode.getParentNode();
                    if (parentProcessNode == null || parentProcessNode.getProcess().getFileName().toLowerCase().contains("explorer")) {
                        return;
                    }
                }


                EventForCS phfEvent = new EventForCS(EventType.PHF, currentClientId, process, timestamp, parentProcessNode.getProcess().getUuid(), "", "");

                currentFramework.addEvent(phfEvent);
                 */
            }
        }
        /*
         * int processId = record.getProcessId(); int threadId = record.getThreadId();
         * long timestamp = record.getTimestamp(); String callStack =
         * record.getCallstack(); TraceKey traceKey = new TraceKey(currentClientId,
         * process, threadId); TraceCache traceCache =
         * traceKey2traceCache.get(traceKey); if (traceCache == null) { traceCache = new
         * TraceCache(traceKey); } traceKey2traceCache.putIfAbsent(traceKey,
         * traceCache); String[] splitCallstack = record.callstack.split(",");
         *
         * if (dumpApi) { DumpAPI.dumpApi(traceKey, callStack); }
         *
         * for (String api : splitCallstack) { if (api.startsWith("Zw")) { api =
         * api.replaceFirst("Zw", "Nt"); } if (api.endsWith("A")) { api =
         * api.substring(0, api.length() - 1) + "W"; } int apiInInteger =
         * ApiToInteger.stringToInteger(api); if (apiInInteger == -1) { continue; }
         * traceCache.insertApi(apiInInteger, false, timestamp); }
         */
    }


    private void processVisibleWindow(EventRecord record) {
        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int left = (int) (long) argument.get("Left");
        int top = (int) (long) argument.get("Top");
        int right = (int) (long) argument.get("Right");
        int bottom = (int) (long) argument.get("Bottom");
        int visible = (int) (long) argument.get("Visible");
        int toolbar = (int) (long) argument.get("Toolbar");
        if (processId != 0 || threadId != 0) {
            currentVisibleWindow.addWindowRecord(processId, left, top, right, bottom, visible, toolbar, timestamp);
        } else {
            currentVisibleWindow.setScreenBoundary(right, bottom);
        }

    }

    private void processFileIoRead(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        String fileName = (String) record.getArgument().get("FileName");
        fileName = fileName.toLowerCase();
        if ("unknown_file".equals(fileName)) {
            return;
        }
        Process process = currentSensitiveFile.addFileReadOrWrite(processId, timestamp, fileName, FileOperation.READ);
        if (!fileName.endsWith(":zone.identifier")) {
            EventForCS event = new EventForCS(EventType.FILE_READ, currentClientId, process, timestamp, fileName, "");
            currentFramework.addEvent(event);
        }
        if (currentFileFromUDisk.checkIfFileFromUDisk(fileName)) {
            LabelForCS label = new LabelForCS(LabelType.FT7, currentClientId, timestamp, fileName);
            currentFramework.addLabel(label);
        }
    }

    private void processFileIoWrite(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();

        String fileName = (String) argument.get("FileName");
        fileName = fileName.toLowerCase();
        if ("unknown_file".equals(fileName)) {
            return;
        }

        Long isDownload = (Long) argument.getOrDefault("IsDownload", 0);
        Process process = currentSensitiveFile.addFileReadOrWrite(processId, timestamp, fileName, FileOperation.WRITE);

        if (!fileName.endsWith(":zone.identifier")) {
            // 排除容易引起下载误报的文件
            if (!excludeExtensionOfDownloadFile.contains(FilenameUtils.getExtension(fileName).toLowerCase())) {
                EventForCS event = new EventForCS(EventType.FILE_WRITE, currentClientId, process, timestamp, fileName, "");
                currentFramework.addEvent(event);

                if (isDownload == 1) {
                    // 客户端检测到的下载,手动传递标签
                    currentFramework.transDownloadLabel(event);
                }
            }
        } else {
            LabelForCS label = new LabelForCS(LabelType.FT6, currentClientId, timestamp, fileName);
            currentFramework.addLabel(label);
        }
        if (currentFileFromUDisk.checkIfFileFromUDisk(fileName)) {
            LabelForCS label = new LabelForCS(LabelType.FT7, currentClientId, timestamp, fileName);
            currentFramework.addLabel(label);
        }
    }

    private void processFileIoRename(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Map<String, Object> arguments = record.getArgument();
        String oldFileName = "";
        if (arguments.containsKey("FileName")) {
            oldFileName = (String) arguments.get("FileName");
        } else if (arguments.containsKey("OldFileName")) {
            oldFileName = (String) arguments.get("OldFileName");
        }
        String newFileName = (String) arguments.get("NewFileName");
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        EventForCS event = new EventForCS(EventType.FILE_RENAME, currentClientId, process, timestamp, oldFileName, newFileName);
        currentFramework.addEvent(event);
    }

    private void processFileIoCreate(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        String fileName = (String) argument.get("OpenPath");
        int hasMacro = (int) (long) argument.get("HasMacro");
        String macroContent = "";
        if (argument.containsKey("MacroContent")) {
            macroContent = argument.get("MacroContent").toString();
        }
        currentMacro.checkIfMacroMalicious(processId, hasMacro, fileName, macroContent, timestamp);
    }

    private void processImageLoad(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        String fileName = String.valueOf(argument.get("FileName"));
        Object isMainModule = argument.get("IsMainModule");
        int certificateState = Integer.valueOf(String.valueOf(argument.getOrDefault("Certificate", "2"))).intValue();
        boolean hasCertificate = certificateState == 1;

        // 忽略加载的驱动
        if (fileName.toLowerCase().endsWith("sys")) {
            return;
        }

        if (isMainModule != null && isMainModule.toString().equals("1")) {
            currentProcessTable.addImageLoad(processId, timestamp, fileName);
            Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);

            certLogger.info("clientId:{} uuid:{} pid:{} fileName:{} Certificate:{}", currentClientId, process.getUuid(), processId, fileName, certificateState);

            if (certificateState == 2) {// 处理第一个ImageLoad事件时，这个事件会最早接收到
                if (fileName.equals(process.getProcessName())) {
                    currentFramework.addEvent(new EventForCS(EventType.LOAD_OWN_EXE, currentClientId, process, timestamp, fileName, ""));
                }
                return;
            }

            currentCertificate.addProcessIdAndFileNameAndIfHasCertificate(processId, fileName, certificateState, timestamp);
        }
    }

    private void processProcessStart(EventRecord record) {
        long timestamp = record.getTimestamp();
        Map<String, Object> map = record.getArgument();
        String fileName = (String) map.get("ImageFileName");
        String commandLine;
        Object rawCommandLine = map.get("CommandLine");
        if (rawCommandLine instanceof String) {
            commandLine = (String) rawCommandLine;
        } else {
            commandLine = Long.toString((long) rawCommandLine);
        }
        int parentId = (int) (long) map.get("ParentId");
        int processId = (int) (long) map.get("ProcessId");

        boolean isDCStart = record.etwEventType == EtwEventType.ProcessDCStart;
        if (isDCStart) {
            Process process = currentProcessTable.isExist(processId, fileName);
            if (process != null) { // 处理ProcessDCStart时 如果Process已存在，则忽略该事件
                process.setUpdateTime(record.timestamp);
                return;
            }
        }
        currentProcessTable.addProcessStart(processId, timestamp, fileName, commandLine, isDCStart);

        Process childProcess = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        Process parentProcess = currentProcessTable.getProcessOrCreateOneIfNotExist(parentId, timestamp);
        EventForCS event = new EventForCS(EventType.PROCESS_START, currentClientId, childProcess, timestamp, parentProcess.getUuid(), "", "");
        currentFramework.addEvent(event);

        if (commandLine.toLowerCase().contains("powershell")) {
            currentPowerShell.checkPowerShellCommand(processId, timestamp, commandLine);
        }

        // 检测敏感程序
        currentSensitiveProgram.addProcessIdAndParentIdAndCommandLineAndFileName(processId, parentId, commandLine, fileName, timestamp);
        // 检测敏感程序，直接上报webportal
        currentSensitiveProgram2.checkSensitiveProgram(processId, parentId, commandLine, fileName, timestamp);
        // 设置Process的updateTime，用于判断collector重启过程中已结束的进程
        childProcess.setUpdateTime(record.timestamp);

        // 检测是否为漏洞程序
        boolean isExploit = Exploit.ExploitCheck(fileName);
        if (isExploit) {
            LabelForCS label = new LabelForCS(LabelType.PT105, currentClientId, childProcess.getUuid(), timestamp, "");
            currentFramework.addLabel(label);
        }

        // 设置collector的启动时间，InitSignal没有时间戳，所以使用第一条VisibelWindowInfo时间的时间戳，作为collector 启动时间
        if (currentProcessTable.getInitTime() == 0) {
            currentProcessTable.setInitTime(record.timestamp);
        }

        // InitSignal执行60s 后执行清理操作
        if (!currentProcessTable.getCleanedFlag() && (record.timestamp - 60000_000000L) > currentProcessTable.getInitTime()) {
            currentProcessTable.clean();
        }
    }

    private void processProcessEnd(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        String fileName = (String) record.getArgument().get("ImageFileName");
        currentProcessTable.addProcessEnd(processId, timestamp, fileName);
        Process process = currentProcessTable.getProcess(processId, timestamp);
        if (process == null) {
            return;
        }
        EventForCS event = new EventForCS(EventType.PROCESS_END, currentClientId, process, timestamp, "", "");
        DetectionFramework framework = currentFramework;
        framework.addEvent(event);

        currentProcessInjection.addProcessEnd(process);
        currentSensitiveProgram.addProcessEnd(processId);
        currentSensitiveProgram2.addProcessEnd(processId);
    }

    private void processThreadEnd(EventRecord record) {
        /*
         * int processId = record.getProcessId(); int threadId = record.getThreadId();
         * long timestamp = record.getTimestamp(); Process process =
         * currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
         * TraceKey traceKey = new TraceKey(currentClientId, process, threadId);
         * TraceCache traceCache = traceKey2traceCache.get(traceKey); if (traceCache ==
         * null) { traceCache = new TraceCache(traceKey); } traceCache.insertApi(null,
         * true, timestamp); traceKey2traceCache.remove(traceKey);
         */
    }

    private static String parseIpAddress(int ipAddress) {
        return String.format("%d.%d.%d.%d", (ipAddress & 0xff), (ipAddress >> 8 & 0xff), (ipAddress >> 16 & 0xff),
                (ipAddress >> 24 & 0xff));
    }

    private void processNetworkConnect(EventRecord record) {
        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int sourcePort = (int) (long) argument.get("sport");
        int destinationPort = (int) (long) argument.get("dport");
        Long sourceIpAddress = Long.valueOf(argument.get("saddr").toString());
        Long destinationIpAddress = Long.valueOf(argument.get("daddr").toString());
        currentNetworkActivity.addNetworkActivity(processId, threadId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, 0, NetworkOperation.NETWORK_CONNECT);
        if (honyPotList.containsKey(currentClientId)) {
            currentNetworkActivity.reportAccessExternalIp(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, "tcp");
        }
        currentThreatIntelligence.checkIp(processId, destinationIpAddress, "tcp", timestamp);
    }

    private void processNetworkClose(EventRecord record) {
        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int sourcePort = (int) (long) argument.get("sport");
        int destinationPort = (int) (long) argument.get("dport");
        Long sourceIpAddress = Long.valueOf(argument.get("saddr").toString());
        Long destinationIpAddress = Long.valueOf(argument.get("daddr").toString());
        Process process = currentProcessTable.getProcess(processId, timestamp);
        if (process == null) {
            return;
        }
        currentNetworkActivity.addNetworkActivity(processId, threadId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, 0, NetworkOperation.NETWORK_CLOSE);
    }

    private void processNetworkSend(EventRecord record) {
        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        Map<String, Object> argument = record.getArgument();
        int sourcePort = (int) (long) argument.get("sport");
        int destinationPort = (int) (long) argument.get("dport");
        Long sourceIpAddress = Long.valueOf(argument.get("saddr").toString());
        Long destinationIpAddress = Long.valueOf(argument.get("daddr").toString());
        //int size = (int)(long)argument.get("size");
        //currentNetworkActivity.addNetworkActivity(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, size, NetworkOperation.NETWORK_SEND);
        currentNetworkActivity.addNetworkActivity(processId, threadId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, 0, NetworkOperation.NETWORK_SEND);

        String protocol = "";
        if (record.etwEventType.equals(EtwEventType.TcpIpSendIPV4)) {
            protocol = "tcp";
        } else if (record.etwEventType.equals(EtwEventType.UdpIpSendIPV4)) {
            protocol = "udp";
        }

        if (honyPotList.containsKey(currentClientId) && (record.etwEventType.equals(EtwEventType.UdpIpSendIPV4) || record.etwEventType.equals(EtwEventType.TcpIpSendIPV4))) {
            currentNetworkActivity.reportAccessExternalIp(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, protocol);
        }

        currentThreatIntelligence.checkIp(processId, destinationIpAddress, protocol, timestamp);

        NetworkEventForCS event = new NetworkEventForCS(EventType.NETWORK_SEND, currentClientId, process, timestamp, sourceIpAddress, destinationIpAddress, sourcePort, destinationPort);
        currentFramework.addEvent(event);
    }

    private void processNetworkRecv(EventRecord record) {
        int processId = record.getProcessId();
        int threadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        Map<String, Object> argument = record.getArgument();
        int sourcePort = (int) (long) argument.get("sport");
        int destinationPort = (int) (long) argument.get("dport");
        Long sourceIpAddress = Long.valueOf(argument.get("saddr").toString());
        Long destinationIpAddress = Long.valueOf(argument.get("daddr").toString());
        //int size = (int)(long)argument.get("size");
        //currentNetworkActivity.addNetworkActivity(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, size, NetworkOperation.NETWORK_RECV);
        currentNetworkActivity.addNetworkActivity(processId, threadId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, 0, NetworkOperation.NETWORK_RECV);

        NetworkEventForCS event = new NetworkEventForCS(EventType.NETWORK_RECV, currentClientId, process, timestamp, sourceIpAddress, destinationIpAddress, sourcePort, destinationPort);
        currentFramework.addEvent(event);

        // 只检测udp协议的recv事件
        if (honyPotList.containsKey(currentClientId) && record.etwEventType.equals(EtwEventType.UdpIpRecvIPV4)) {
            // udp 中 saddr sport 是 对方的ip和端口
            //currentNetworkActivity.reportNetwork(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, "udp");
            currentNetworkActivity.reportPortAccessed(processId, timestamp, destinationIpAddress, destinationPort, sourceIpAddress, sourcePort, "udp");
        }
        // TcpIpAccept事件可能未收到，针对Tcp的端口被访问事件，增加判断条件 TcpIpRecvIPV4
        if (honyPotList.containsKey(currentClientId) && record.etwEventType.equals(EtwEventType.TcpIpRecvIPV4)) {
            // tcp 中 daddr和dport是对方的ip和端口
            currentNetworkActivity.reportPortAccessed(processId, timestamp, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort, "tcp");
        }
    }

    private void processPowerShell(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        String commandLine = record.getArgument().get("CommandLine").toString();
        currentPowerShell.checkPowerShellCommand(processId, timestamp, commandLine);
    }

    private void processMacro(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        try {
            String fileName = (String) argument.get("FileName");
            int hasMacro = (int) (long) argument.get("MacroResult");
            String macroContent = "";
            if (argument.containsKey("MacroContent")) {
                macroContent = (String) argument.get("MacroContent");
            }
            currentMacro.checkIfMacroMalicious(processId, hasMacro, macroContent, fileName, timestamp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processThreadStart(EventRecord record) {
        int parentProcessId = record.getProcessId();
        int parentThreadId = record.getThreadId();
        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        int childProcessId = (int) (long) argument.get("ProcessId");
        int childThreadId = (int) (long) argument.get("TThreadId");
        currentProcessInjection.addThreadStart(parentProcessId, parentThreadId, childProcessId, childThreadId, timestamp);
    }

    private void processFileIoFileCreate(EventRecord record) {
        /*
         * Map argument = record.getArgument(); String fileName =
         * (String)argument.get("FileName"); long timeDateStamp =
         * (long)argument.get("TimeDateStamp"); if (timeDateStamp < 1800) { LabelForCS
         * label = new LabelForCS("FT8"); label.stringField = fileName;
         * currentFramework.addLabel(label); }
         */
    }

    private void processDeviceRemovable(EventRecord record) {
        /*
        String volumeId = (String) record.getArgument().get("CommandLine");
        currentFileFromUDisk.addUDiskVolumeId(volumeId);
         */

        long timestamp = record.getTimestamp();
        Map<String, Object> argument = record.getArgument();
        String serialNumber = argument.get("SerialNumber").toString();
        String rootPath = argument.get("RootPath").toString();
        String volumeName = argument.get("VolumeName").toString();
        String fileSystem = argument.get("FileSystem").toString();
        logger.info("DeviceRemoveable clientId:{} serialNumber:{} rootPath:{} volumeName:{} fileSystem:{}", currentClientId, serialNumber, rootPath, volumeName, fileSystem);

        // 直接上报
        Reporter.reportDeviceRemoveable(currentClientId, serialNumber, rootPath, volumeName, fileSystem, timestamp);
    }

    private void processFileIoDelete(EventRecord record) {
        int processId = record.getProcessId();
        long timestamp = record.getTimestamp();
        String fileName = (String) record.getArgument().get("FileName");
        Process process = currentProcessTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        currentFramework.addEvent(new EventForCS(EventType.FILE_DELETE, currentClientId, process, timestamp, fileName, ""));
    }

    private void processHealthCheck(EventRecord record) {
        logger.info(currentClientId + " health check event:" + record.toString());
        if (!record.argument.containsKey("CheckID")) {
            return;
        }

        if (CompilationConfig.DEBUG) {
            return;
        }
        HealthCheckReporter.report(String.valueOf(record.argument.get("CheckID")), currentClientId);
    }

    private void processInitSignal(EventRecord record) {

        String clientId = currentClientId;
        // 每次collector重启 重置 布隆过滤器 ，否则事件因被去重，而产生的没有检测结果的问题
        DeduplicatingEvent.removeClient(clientId);

        long currentDeviceBootTime = (long) record.argument.get("DeviceBootTime");
        Boolean honeyPot = honyPotList.containsKey(clientId);
        ssLogger.info("InitSignal clientId:{} DeviceBootTime:{} honeyPot:{}", clientId, currentDeviceBootTime, honeyPot);
        ProcessTable processTable = ProcessTable.getInstance(clientId);

        // 当detector启动时应该进行恢复快照，该标志表示ProcessTable中是否有数据
        boolean restoreSnapshot = false;
        if (processTable != null && Math.abs(processTable.getDeviceBootTime() - currentDeviceBootTime) > 10) {
            restoreSnapshot = true;
            ProcessTable.removeClient(clientId);
            Certificate.removeClient(clientId);
            Macro.removeClient(clientId);
            NetworkActivity.removeClient(clientId);
            PowerShell.removeClient(clientId);
            ProcessInjection.removeClient(clientId);
            SensitiveFile.removeClient(clientId);
            SensitiveProgram.removeClient(clientId);
            SensitiveProgram2.removeClient(clientId);
            VisibleWindow.removeClient(clientId);
            FileFromUDisk.removeClient(clientId);
            DetectionFramework.resetClient(clientId);
            AutoRunInfo.removeClient(clientId);
            ThreatIntelligence.removeClient(clientId);
        }
        setCurrent(clientId);
        logger.info("reset client {}", clientId);

        currentTotalEventFromInitSignal.set(0);
        outputEventCount(clientId, currentTotalEvent, currentTotalEventFromInitSignal, currentTotalPacket, currentDuplicateEvent, true);

        currentProcessTable.setInitTime(0);
        currentProcessTable.setInitTime2();
        currentProcessTable.setDeviceBootTime(currentDeviceBootTime);

        // 当前事件的DeviceBootTime等于快照中的DeviceBootTime说明，该快照可以用于恢复
        // 恢复后应该立即删除快照,否则会造成一份快照，多次恢复，引起的数据错乱问题
        // 恢复时应注意restoreSnapshot应为true，表示检测数据为空
        long deviceBootTimeFromSnapshot = Snapshot.getDeviceBootTimeFromSnapshot(clientId);
        ssLogger.info("clientId:{} deviceBootTimeFromSnapshot:{}", clientId, deviceBootTimeFromSnapshot);

        // 发现DeviceBootTime会有误差
        if ((Math.abs(currentDeviceBootTime - Snapshot.getDeviceBootTimeFromSnapshot(clientId)) < 10) && restoreSnapshot) {
            ssLogger.info("{} 开始恢复备份", clientId);
            long start = System.currentTimeMillis();

            // 用于生成dump文件夹名称
            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("YYYY-MM-dd-HH-mm-ss");
            String dumpDir = now.format(dtf);

            currentProcessTable.setDeviceBootTime(deviceBootTimeFromSnapshot);

            // restore process table
            HashMap<Integer, ProcessInfo> processInfoList = Snapshot.getProcessInfoList(clientId);
            if (dumpSnapshot) {
                Snapshot.dumpProcessTable(clientId, dumpDir, processInfoList.values());
            }
            processInfoList.values().forEach(p -> {
                Process process = new Process(p.getUuid(),
                        clientId, p.getPid(),
                        p.getStartTime(),
                        p.getEndTime(),
                        p.getAnyMiddleTime(),
                        p.getFileName(),
                        p.getProcessName(),
                        p.getCmd(),
                        p.getUpdateTime()
                );
                // uuid2Process
                currentProcessTable.getUuid2Process().put(p.getUuid(), process);

                // processId2ProcessList
                ConcurrentSkipListSet<Process> processes = currentProcessTable.getProcessId2ProcessList().getOrDefault(p.getPid(), new ConcurrentSkipListSet<>());
                processes.add(process);
                currentProcessTable.getProcessId2ProcessList().putIfAbsent(p.getPid(), processes);

                // uuid counter
                if (p.getUuid() > Process.counter.get()) {
                    Process.counter.set(p.getUuid());
                }

                // restore framework
                if (p.getUuid() > 0) {
                    ProcessNode processNode = new ProcessNode(process);
                    processNode.setLabelList(p.getLabel());
                    currentFramework.getProcessMap().put(process.getUuid(), processNode);
                }
            });

            ssLogger.info("{} ProcessTable uuid2Process {} restore process {}",
                    clientId,
                    currentProcessTable.getUuid2Process().size(),
                    processInfoList.size()
            );

            ssLogger.info("{} FrameWork processMap size: {}", clientId, currentFramework.getProcessMap().size());

            // set parentProcessNode
            currentFramework.getProcessMap().values().forEach(processNode -> {
                // processNode.getUuid()获取的是Long类型，需要转型int，否则获取到的是null
                ProcessInfo processInfo = processInfoList.get((int) processNode.getUuid());
                ProcessNode parentProcessNode = currentFramework.getProcessMap().get(processInfo.getPuuid());
                if (parentProcessNode != null) {
                    processNode.setParentNode(parentProcessNode, false);
                } else {
                    processNode.setParentNode(currentFramework.getProcessRoot(), false);
                }
            });

            // restore process injection
            List<Integer> attackerUuids = Snapshot.getAttackerUuids(clientId);
            if (dumpSnapshot) {
                Snapshot.dumpProcessInjectionAttacker(clientId, dumpDir, attackerUuids);
            }

            attackerUuids.forEach(uuid -> {
                Process process = currentProcessTable.getUuid2Process().get(uuid);
                if (process == null) {
                    return;
                }
                currentProcessInjection.getAttackers().add(process);
            });

            ssLogger.info("{} ProcessInjection attacker count: {} restore attacker count: {}",
                    clientId,
                    currentProcessInjection.getAttackers().size(),
                    attackerUuids.size()
            );

            List<ThreadInfo> threadInfoList = Snapshot.getVictimThreadList(clientId);
            if (dumpSnapshot) {
                Snapshot.dumpProcessInjectionvictimThread(clientId, dumpDir, threadInfoList);
            }

            threadInfoList.forEach(threadInfo -> {
                Process process = currentProcessTable.getUuid2Process().get(threadInfo.getPuuid());
                if (process == null) {
                    return;
                }
                Process attackerProcess = currentProcessTable.getUuid2Process().get(threadInfo.getAttackerUuid());
                if (attackerProcess == null) {
                    return;
                }

                etwThread thread = new etwThread(process, threadInfo.getThreadId(), threadInfo.getUpdateTime());
                currentProcessInjection.getVictimThread2Attacker().put(thread, attackerProcess);

                Set<etwThread> victimThreads = currentProcessInjection.attacker2VictimThreads.getOrDefault(process, new HashSet<>());
                victimThreads.add(thread);
                currentProcessInjection.attacker2VictimThreads.putIfAbsent(attackerProcess, victimThreads);
            });

            ssLogger.info("{} processInjection victimThreadAttacker size() {} attacker2VictimThread.size() {} restoreVictimThreadCount {}",
                    clientId,
                    currentProcessInjection.getVictimThread2Attacker().size(),
                    currentProcessInjection.attacker2VictimThreads.size(),
                    threadInfoList.size()
            );

            // restore file node 废弃
            //FileNodeNew fileNodeNew = FileNodeNew.getInstance(clientId);
            //HashMap<String, byte[]> filterMap = Snapshot.getFileNodeByteArray(clientId);
            //byte[] fileNodeFilter = filterMap.get("files");
            //byte[] fileLabelFilter = filterMap.get("fileLabels");
            //fileNodeNew.setFilePathFilter(fileNodeFilter);
            //fileNodeNew.setFileLabelFilter(fileLabelFilter);
            //ssLogger.info("{} fileNodeFilter: {} fileLabelFilter: {}", clientId, fileNodeFilter.length, fileLabelFilter.length);

            // restore sensitive program2
            Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramInfos = Snapshot.getSensitiveProgram2(clientId);
            if (dumpSnapshot) {
                Snapshot.dumpSensitiveProgram2(clientId, dumpDir, processId2SensitiveProgramInfos);
            }
            currentSensitiveProgram2.getProcessId2SensitivePrograms().putAll(processId2SensitiveProgramInfos);
            logger.info("{} SensitiveProgram2 snapshot: {} after: {}", clientId, processId2SensitiveProgramInfos.values().size(), currentSensitiveProgram2.getProcessId2SensitivePrograms().size());

            ssLogger.info("{} SensitiveProgram2 processId count: {} sensitiveProgram count: {} restoreSensitiveProgram2 {}",
                    clientId,
                    currentSensitiveProgram2.getProcessId2SensitivePrograms().size(),
                    currentSensitiveProgram2.getProcessId2SensitivePrograms().values().size(),
                    processId2SensitiveProgramInfos.values().size()
            );

            // restore sensitive program
            Map<Integer, HashSet<String>> processId2SensitiveProgram = Snapshot.getSensitiveProgram(clientId);
            currentSensitiveProgram.getProcessId2SensitivePrograms().putAll(processId2SensitiveProgram);

            ssLogger.info("{} SensitiveProgram processId count: {} sensitiveProgram count: {} restoreSensitiveProgram {}",
                    clientId,
                    currentSensitiveProgram.getProcessId2SensitivePrograms().size(),
                    currentSensitiveProgram.getProcessId2SensitivePrograms().values().size(),
                    processId2SensitiveProgram.values().size()
            );

            long end = System.currentTimeMillis();
            ssLogger.info("{} 恢复备份完成 耗时 {}ms", clientId, (end - start));
        }
        // 快照恢复后或者快照数据不可用，都将快照数据删除
        // delete snapshot
        Snapshot.deleteSnapshot(clientId);
    }


    private void processAutorunInfo(EventRecord record) {
        if (!record.argument.containsKey("FileName")) {
            return;
        }

        String files = record.argument.get("FileName").toString();

        if (files == null || files.isEmpty()) {
            return;
        }
        logger.info(currentClientId + " AutoRunInfo:" + files);
        currentAutoRunInfo.processAutoRunInfo(files);
    }

    private static synchronized void outputEventCount(String clientId, AtomicLong totalEvent, AtomicLong currentTotalEventFromInitSignal, AtomicLong totalPacket, AtomicLong duplicates, boolean init) {
        ouputBuilder.delete(0, ouputBuilder.length());
        try (BufferedWriter pw = new BufferedWriter(new FileWriter("ReceiveEventCount.txt", true))) {
            LocalDateTime now = LocalDateTime.now();
            String nowText = now.format(formatter);
            ouputBuilder.append(nowText).append(":");
            ouputBuilder.append(" clientId=").append(clientId);
            ouputBuilder.append(" totalPacket=").append(totalPacket.get());
            ouputBuilder.append(" totalEvent=").append(totalEvent.get());
            ouputBuilder.append(" duplicate=").append(duplicates.get());
            ouputBuilder.append(" processedEvent=").append(totalEvent.get() - duplicates.get());
            long from = ProcessTable.getInstance(clientId).getInitTime2();
            long to = System.currentTimeMillis() / 1000;
            long diff = to - from;
            if (diff > 0) {
                long count = currentTotalEventFromInitSignal.longValue() / diff;
                ouputBuilder.append(" ").append(count).append("/s");
            } else {
                ouputBuilder.append(" 0/s");
            }
            if (init) {
                ouputBuilder.append(" InitSignal");
            }

            pw.write(ouputBuilder.toString());
            pw.newLine();
        } catch (Exception e) {
            logger.error("pw error", e);
        }
    }

    private static synchronized void outputCallstackCount(String clientId, AtomicLong totalEvent, AtomicLong totalPacket, AtomicLong duplicates, AtomicLong totalCallstack,AtomicLong totalSize,AtomicLong totalCallstackSize, AtomicLong CPUTime,AtomicLong CallstackCPUTime, AtomicLong preTime) {
        ouputBuilder.delete(0, ouputBuilder.length());

        try (BufferedWriter pw = new BufferedWriter(new FileWriter("ReceiveCallStackCount.txt", true))) {
            if(preTime.get() == 0L)
            {
                preTime.set(System.currentTimeMillis());
                ouputBuilder.append("time clientId totalPacket totalEvent duplicate processedEvent totalCallstack totalSize totalCallstackSize CPUTime CallstackCPUTime timeInterval");
                pw.write(ouputBuilder.toString());
                pw.newLine();
                ouputBuilder.delete(0, ouputBuilder.length());
            }
            LocalDateTime now = LocalDateTime.now();
            String nowText = now.format(formatter);
            ouputBuilder.append(nowText);
            ouputBuilder.append(" ").append(clientId);
            ouputBuilder.append(" ").append(totalPacket.get());
            ouputBuilder.append(" ").append(totalEvent.get());
            ouputBuilder.append(" ").append(duplicates.get());
            ouputBuilder.append(" ").append(totalEvent.get() - duplicates.get());
            ouputBuilder.append(" ").append(totalCallstack);
            ouputBuilder.append(" ").append(totalSize);
            ouputBuilder.append(" ").append(totalCallstackSize);
            ouputBuilder.append(" ").append(CPUTime);
            ouputBuilder.append(" ").append(CallstackCPUTime);
            long nowM = System.currentTimeMillis();
            long preM = preTime.get();
            long diff = nowM - preM;
            preTime.set(nowM);
            ouputBuilder.append(" ").append(diff);
            pw.write(ouputBuilder.toString());
            pw.newLine();
        } catch (Exception e) {
            logger.error("pw error", e);
        }
    }

}
