package NU.ETWRealTimeDetector.Framework;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.NetworkActivity;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.ProcessInjection;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.SensitiveProgram2;
import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Grammar.*;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.*;
import NU.ETWRealTimeDetector.Framework.Node.filenode.FileNodeManager;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Pojo.SensitiveProgram2Info;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.Util.CacheHelper;
import NU.ETWRealTimeDetector.Util.DeduplicatingEvent;
import NU.ETWRealTimeDetector.Util.MD5;
import org.ehcache.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class DetectionFramework {
    private final String clientId;
    private static final Logger logger = LoggerFactory.getLogger(DetectionFramework.class);
    private static final Logger judgeLogger = LoggerFactory.getLogger("judge");
    private static Map<String, DetectionFramework> clientId2instance = new HashMap<>();
    private static Map<String, Integer> judgeMode2AlertLevel;
    private static Map<String, Integer> monitorJudgeMode2AlertLevel;
    private static List<String> trustList = new ArrayList<>();

    public static synchronized DetectionFramework getInstance(String clientId) {
        DetectionFramework instance = clientId2instance.get(clientId);
        if (instance == null) {
            instance = new DetectionFramework(clientId);
            clientId2instance.put(clientId, instance);
        }
        return instance;
    }

    public static Map<String, DetectionFramework> getClientId2instance() {
        return clientId2instance;
    }

    public static void resetClient(String clientId) {
        if (clientId2instance.containsKey(clientId)) {
            DetectionFramework temp;
            String key = null;
            try {
                temp = clientId2instance.get(clientId);
                //temp.fileNodeNew.destory();
                if (temp != null) {
                    key = temp.key;
                    //CacheHelper.remove(key);
                    CacheHelper.removeMonitorCache(key);
                }
            } catch (Exception e) {
                logger.error(String.format("remove cache error. clientId %s client2instance.containsKey(%s) %b temp.key %s ", clientId, clientId2instance.containsKey(clientId), key), e);
            }
            clientId2instance.remove(clientId);
        }
    }

    private TransGrammar transGrammar;
    private LabelGrammar labelGrammar;
    private JudgeGrammar judgeGrammar;
    private JudgeGrammar monitorJudgeGrammar;

    //private Map<String, FileNode> fileMap = new HashMap<>();
    private ConcurrentHashMap<Integer, ProcessNode> processMap = new ConcurrentHashMap<>();
    private ProcessNode processRoot;

    private Neo4jClient neo4jClient = Neo4jClient.getInstance();

    private final String key;
    //private final Cache<String, FileNode> fileMap;
    private final Cache<String, String> monitorResult;
    //private final FileNodeNew fileNodeNew;

    // 检测出的恶意进程uuid 和 最后一次画图时间，当该进程的子及孙子进程启动时，触发刷新画图，当该进程结束后，停止上报
    private final HashMap<Integer, Long> suspectProcess2lastReportTime = new HashMap<>();
    private final HashMap<Integer, Long> suspectProcess2lastDrawTime = new HashMap<>();

    private DetectionFramework(String clientId) {
        this.clientId = clientId;
        transGrammar = new TransGrammar("trans.txt");
        labelGrammar = new LabelGrammar("label.txt");
        judgeGrammar = new JudgeGrammar("judge.txt");
        monitorJudgeGrammar = new JudgeGrammar("monitor_judge.txt");
        judgeMode2AlertLevel = judgeGrammar.getJudgeMode2AlertLevel();
        monitorJudgeMode2AlertLevel = monitorJudgeGrammar.getJudgeMode2AlertLevel();

        ProcessTable processTable = ProcessTable.getInstance(clientId);
        Process root = processTable.getProcessOrCreateOneIfNotExist(0, 0);
        processRoot = new ProcessNode(root);
        new File("txt/" + clientId + "/").mkdirs();
        new File("graph/" + clientId + "/").mkdirs();
        new File("dot/" + clientId + "/").mkdirs();
        key = clientId + this.hashCode();
        //fileMap = CacheHelper.getFileNodeCache(key);
        monitorResult = CacheHelper.getMonitorCache(key);
        //this.fileNodeNew = FileNodeNew.getInstance(clientId);
        trustList.add("magicmessager.exe");
        trustList.add("magicservice.exe");
    }

    private void insertNewNodeUnderRoot(ProcessNode newNode) {
        processMap.put(newNode.getProcess().getUuid(), newNode);
        processRoot.getChildNodes().add(newNode);
        newNode.setParentNode(processRoot, false);
    }

    private ProcessNode getProcessNodeByEvent(EventForCS event) {
        ProcessNode processNode = processMap.get(event.getProcess().getUuid());
        if (processNode == null) {
            processNode = new ProcessNode(event.getProcess());
            insertNewNodeUnderRoot(processNode);
        }
        return processNode;
    }

    private ProcessNode getProcessNodeByUuid(int uuid, String clientId) {
        ProcessTable processTable = ProcessTable.getInstance(clientId);
        ProcessNode processNode = processMap.get(uuid);
        if (processNode == null) {
            processNode = new ProcessNode(processTable.getProcessByUuid(uuid));
            insertNewNodeUnderRoot(processNode);
        }
        return processNode;
    }

    private FileNodeNew getFileNodeBySignal(ISignalForCS signal) {
        //boolean isRightPath = StringUtil.isPathRight(signal.getFileName());
        //if (isRightPath) {
//            List<FileNode> wrongPathList = fileMap.values().stream().filter(f -> !f.isPathRight()).filter(f -> signal.getFileName().contains(f.getFilePath())).collect(Collectors.toList());
//            wrongPathList.forEach(f -> {
//                fileMap.remove(f.getFilePath());
//                // 当正确的盘符路径找到时，需要更新到neo4j，File_rename会通过rename更新，其他事件，如File_Read File_Write需要额外处理
//                boolean affectNeo4j = signal.isEvent() && ((EventForCS) signal).getType() != EventType.FILE_RENAME;
//                f.setFilePath(signal.getFileName(), affectNeo4j);
//                fileMap.put(f.getFilePath(), f);
//            });
        //}

        //if (fileNode == null) {
        //    if (signal.isEvent()) {
        //        if (((EventForCS) signal).getType() == EventType.FILE_READ || ((EventForCS) signal).getType() == EventType.FILE_DELETE || ((EventForCS) signal).getType() == EventType.FILE_RENAME) {
        //            return null;
        //        }
        //    }
        //    fileNode = new FileNode(signal.getFileName(), signal.getClientId());
        //    fileMap.put(fileNode.getFilePath(), fileNode);
        //}

        //boolean isExist = fileNodeNew.isExist(signal.getFileName());
        //if (!isExist) {
        //    if (signal.isEvent()) {
        //        if (((EventForCS) signal).getType() == EventType.FILE_READ || ((EventForCS) signal).getType() == EventType.FILE_DELETE || ((EventForCS) signal).getType() == EventType.FILE_RENAME) {
        //            return null;
        //        }
        //    }
        //}
        //fileNodeNew.setFileName(signal.getFileName());
        //if (!isExist) {
        //    neo4jClient.addFileNode(fileNodeNew);
        //}
        //return fileNodeNew;
        return null;
    }

    private FileNodeV2 getFileNodeV2BySignal(ISignalForCS signal) {
        FileNodeV2 fileNodeV2 = FileNodeManager.get(this.clientId, signal.getFileName());
        if (fileNodeV2 == null) {
            // 如果文件不存在，并且处理的事件时File_READ等不会反向传递,则忽略
            if (signal.isEvent()) {
                if (((EventForCS) signal).getType() == EventType.FILE_READ || ((EventForCS) signal).getType() == EventType.FILE_DELETE || ((EventForCS) signal).getType() == EventType.FILE_RENAME) {
                    return null;
                }
            }

            fileNodeV2 = new FileNodeV2(clientId, signal.getFileName());
            FileNodeManager.set(fileNodeV2);
            neo4jClient.addFileNodeV2(fileNodeV2);
        }
        return fileNodeV2;
    }

    public ProcessNode getProcessRoot() {
        return this.processRoot;
    }

    public FileNodeV2 getFileNodeV2(String fileName) {
        FileNodeV2 fileNodeV2 = FileNodeManager.get(this.clientId, fileName);
        if (fileNodeV2 == null) {
            fileNodeV2 = new FileNodeV2(this.clientId, fileName);
            FileNodeManager.set(fileNodeV2);
            neo4jClient.addFileNodeV2(fileNodeV2);
        }
        return fileNodeV2;
    }

    public void addEvent(EventForCS event) {

        ProcessNode processNode = getProcessNodeByEvent(event);

        switch (event.getType()) {
            case PROCESS_START:
                ProcessNode parentNode = getProcessNodeByUuid(event.getParentUuid(), event.getClientId());
                processProcessStartEvent(event, processNode, parentNode);
                break;
            case PROCESS_END:
                processProcessEndEvent(event, processNode);
                break;
            case NETWORK_SEND:
            case NETWORK_RECV:
                processNetworkEvent(event, processNode);
                break;
            case FILE_CREATE:
            case FILE_READ:
            case FILE_RENAME:
            case FILE_WRITE:
            case FILE_DELETE:
                FileNodeV2 fileNode = getFileNodeV2BySignal(event);
                if (fileNode == null) {
                    return;
                }
                processFileEvent(event, processNode, fileNode);
                break;
            case LOAD_OWN_EXE:
                FileNodeV2 imageFileNode = getFileNodeV2BySignal(event);
                processLoadOwnExeEvent(event, processNode, imageFileNode);
                break;
            case Zone_Identifier:
                imageFileNode = getFileNodeV2BySignal(event);
                processZoneIdentifier(event, processNode, imageFileNode);
                break;
            case INJECTION:
            case INJECTION2:
            case PHF:
            case START_SCRIPT:
                ProcessNode attackerNode = getProcessNodeByUuid(event.getParentUuid(), event.getClientId());
                processInjectionOrScriptEvent(event, processNode, attackerNode);
                break;
            case REMOTE_THREAD_PHF:
                attackerNode = getProcessNodeByUuid(event.getParentUuid(), event.getClientId());
                processRemoteThreadPhfEvent(event, processNode, attackerNode);
                break;
            default:
                break;
        }
    }

    private void processProcessStartEvent(EventForCS event, ProcessNode childNode, ProcessNode parentNode) {
        if (event.getParentUuid() != event.getProcess().getUuid()) {
            if (childNode.getParentNode() != null) {
                childNode.getParentNode().getChildNodes().remove(childNode);
            }
            parentNode.getChildNodes().add(childNode);
            childNode.setParentNode(parentNode, true);
            transLabel(parentNode, childNode, event.getType(), TransDirection.TWOWAY, event.getTimestamp());

        }
    }

    public void removeProcessNode(int uuid) {
        if (processMap == null || !processMap.containsKey(uuid)) {
            return;
        }
        ProcessNode processNode = processMap.get(uuid);
        processMap.remove(uuid);
        suspectProcess2lastReportTime.remove(uuid);
        suspectProcess2lastDrawTime.remove(uuid);

        ProcessNode parentNode = processRoot;
        if (processNode.getParentNode() != null) {
            parentNode = processNode.getParentNode();
            parentNode.getChildNodes().remove(processNode);
        }
        for (ProcessNode childNode : processNode.getChildNodes()) {
            childNode.setParentNode(parentNode, false);
        }
    }

    public void processProcessEndEvent(EventForCS event, ProcessNode processNode) {
//        ProcessInjection injection = ProcessInjection.getInstance(processNode.getClientId());
//        if (injection.possibleAttacker2VictimThreads.containsKey(processNode.getProcess())
//                || injection.attacker2VictimThreads.containsKey(processNode.getProcess())) {
//            return;
//        }

//        if (processMap.containsValue(processNode) && !dyingFileNodes.contains(processNode)) {
//            dyingProcessNodeUuid.add(processNode.getProcess().getUuid());
//            if (dyingProcessNodeUuid.size() > dyingNodesLimit) {
//                Integer uuid = dyingProcessNodeUuid.poll();
//                if (uuid != null) {
//                    removeProcessNode(uuid.intValue());
//                }
//            }
//        }
    }

    private void processFileEvent(EventForCS event, ProcessNode processNode, FileNodeV2 fileNodeV2) {
        if (event.getType() == EventType.FILE_DELETE) {
            return;
        }
        if (event.getType() == EventType.FILE_RENAME) {
            if (event.getOldName().equals(event.getNewName())) {
                return;
            }
            long oldFileNodeUuid = fileNodeV2.getUuid();
            Set<LabelType> oldLabels = fileNodeV2.getLabels();

            // 如果重命名的文件不存在则创建一个新的FileNode
            FileNodeV2 newFileNode = FileNodeManager.get(clientId, event.getNewName());

            if (newFileNode == null) {
                newFileNode = new FileNodeV2(clientId, event.getNewName());
                FileNodeManager.set(newFileNode);
                neo4jClient.addFileNodeV2(newFileNode);
                // 将illustrator中保存在oldFileNode上的label 转移到 newFileNode上
                neo4jClient.renameFile(clientId, oldFileNodeUuid, newFileNode.getUuid(), event.getNewName());
            }

            final FileNodeV2 finalNewFileNode = newFileNode;
            oldLabels.forEach(label -> finalNewFileNode.addLabel(label));

            return;
        }

        transLabel(processNode, fileNodeV2, event.getType(), TransDirection.TWOWAY, event.getTimestamp());
    }

    public void transDownloadLabel(EventForCS event) {
        ProcessNode processNode = getProcessNodeByEvent(event);
        if (processNode == null) {
            return;
        }

        FileNodeV2 fileNodeV2 = getFileNodeV2BySignal(event);
        if (fileNodeV2 == null) {
            return;
        }
        // 手动传递标签 PT1-[FileIoWrite]->FT1
        performTransfer(processNode, fileNodeV2, TransDirection.DIRECT, event.getType(), LabelType.PT1, LabelType.FT1, null, event.getTimestamp());
    }

    private void processZoneIdentifier(EventForCS event, ProcessNode processNode, FileNodeV2 fileNodeV2) {
        transLabel(processNode, fileNodeV2, EventType.LOAD_OWN_EXE, TransDirection.TWOWAY, event.getTimestamp());
    }

    private void processLoadOwnExeEvent(EventForCS event, ProcessNode processNode, FileNodeV2 fileNodeV2) {

        logger.debug("before trans: processNode:" + processNode + " " + processNode.getLabels() + " fileNode:" + fileNodeV2.getUuid() + " " + fileNodeV2 + " " + fileNodeV2.getLabels());
        transLabel(processNode, fileNodeV2, event.getType(), TransDirection.TWOWAY, event.getTimestamp());
        //fileMap.put(fileNode.getFilePath(), fileNode);
        logger.debug("after trans: processNode:" + processNode + " " + processNode.getLabels() + " fileNode:" + fileNodeV2.getUuid() + " " + fileNodeV2 + " " + fileNodeV2.getLabels());

        // ProcessStart事件的处理 进行了敏感程序检测，如果一个程序执行了敏感程序 需要上报给webportal,但在ProcessStart事件中，子进程还没有ProcessName，因此 等子进程 ImageLoad事件时，补全了ProcessName再画进程关系图，并上报给webportal

        // 获取父进程执行的敏感程序
        Process parentProcess = processNode.getParentNode().getProcess();
        int parentProcessId = parentProcess.getProcessId();
        if (parentProcess.getProcessId() != 0) {
            // sensitivePrograms中保存的是filename 去掉.exe
            HashMap<String, SensitiveProgram2Info> sensitivePrograms = SensitiveProgram2.getInstance(clientId).getSensitiveProgram(parentProcessId);
            if (sensitivePrograms != null && !sensitivePrograms.isEmpty()) {
                // 判断当前进程是不是父进程执行的敏感程序，如果是，画进程关系图 并上报
                SensitiveProgram2Info info = sensitivePrograms.get(processNode.getProcess().getFileName().toLowerCase().replace(".exe", ""));

                // 5分钟上报一次
                if (info != null && info.needReport(event.getTimestamp())) {
                    HashMap<String, String> extend = new HashMap<>();
                    extend.put("subProcessId", String.valueOf(processNode.getProcess().getProcessId()));
                    extend.put("subProcessUuid", String.valueOf(processNode.getUuid()));
                    extend.put("sensitiveProgram", processNode.getProcess().getFileName());
                    extend.put("count", String.valueOf(info.getCount()));
                    neo4jClient.drawSensitiveProgramProcessRelationGraph(clientId, parentProcess, String.join(",", sensitivePrograms.keySet()), extend);
                }
            }
        }

        ProcessNode parentOrAncestorProcess = processNode.getParentNode();
        //ProcessNode currentProcessNode = processNode;
        // 判断该进程的父进程及祖先进程是否为恶意应用，如果是恶意应用刷新画图
        int i = 0;
        while (i++ < 20) {
            if (parentOrAncestorProcess == null || parentOrAncestorProcess.equals(processRoot)) {
                break;
            }

            int parentOrAncestorProcessUuid = parentOrAncestorProcess.getProcess().getUuid();
            if (suspectProcess2lastReportTime.containsKey(parentOrAncestorProcessUuid)) {
                // neo4jClient.drawAttackGraph(clientId, processNode.getProcess());
                // 判断上一次的上报时间

                long now = System.currentTimeMillis();
                Long lastReportTime = suspectProcess2lastReportTime.get(parentOrAncestorProcessUuid);
                if (lastReportTime == null) {
                    break;
                }
                long diff = now - lastReportTime;
                // 如果上一次的上报时间大于30s则更新画图
                if (diff > 30000) {
                    String eventId = UUID.nameUUIDFromBytes(String.valueOf(processNode.getUuid()).getBytes()).toString();
                    neo4jClient.drawProcessRelationGraph(clientId, parentOrAncestorProcess.getProcess(), eventId);
                    suspectProcess2lastReportTime.put(parentOrAncestorProcessUuid, now);
                }
                break;
            }

            parentOrAncestorProcess = parentOrAncestorProcess.getParentNode();
        }
    }

    private void processInjectionOrScriptEvent(EventForCS event, ProcessNode childNode, ProcessNode parentNode) {
        transLabel(parentNode, childNode, event.getType(), TransDirection.TWOWAY, event.getTimestamp());
    }

    private void processRemoteThreadPhfEvent(EventForCS event, ProcessNode childNode, ProcessNode parentNode) {
        transLabel(parentNode, childNode, event.getType(), TransDirection.REVERSE, event.getTimestamp());
    }

    // TODO
    private void processNetworkEvent(EventForCS event, ProcessNode localNode) {
    }

    public Map<Integer, ProcessNode> getProcessMap() {
        return processMap;
    }

    public ProcessNode getProcessNode(int uuid) {
        return processMap.get(uuid);
    }

    //public boolean haveNewFileData() {
    //    return fileNodeNew.haveNewData();
    //}

    //public byte[] getFileLabelBloomFilterBytes() {
    //    return fileNodeNew.getFileLabelFilterBytes();
    //}

    //public byte[] getFilePathBloomFilterBytes() {
    //    return fileNodeNew.getFileNodeFilterBytes();
    //}

    public void addLabel(LabelForCS label) {
        if (label == null) {
            return;
        }

        Node node;
        if (label.isFileLabel()) {
            node = getFileNodeV2BySignal(label);
        } else {
            node = getProcessNodeByUuid(label.getUuid(), label.getClientId());
        }
        boolean isFirstAddLabel = !node.getLabels().contains(label.getType());

        node.addLabel(label.getType());
        //if (label.isFileLabel()) {
        //    FileNode fileNode = ((FileNode) node);
        //    fileMap.put(fileNode.getFilePath(), fileNode);
        //}

        if (isFirstAddLabel) {
            neo4jClient.addLabel(clientId, node, node, label.getType(), label.getType(), EventType.NOTHING, label.getTimestamp() / 1000000L, label.getExtend());
        }
        if (label.getType().equals(LabelType.PT12) || label.getType().equals(LabelType.PT72)) {
            neo4jClient.addProperty(node, "SensitiveProgram", label.getStringField());
        }
        if (node.needsJudgeNow()) {
            judgeNode(node, label.getType());
            node.turnOffJudgeNow();
        }
    }

    private boolean transLabel(Node subjectNode, Node objectNode, EventType eventType, TransDirection direction, long timestamp) {
        boolean hasTrans = false;
        if (direction == TransDirection.DIRECT || direction == TransDirection.TWOWAY) {
            for (LabelType labelType : subjectNode.getLabels()) {
                TransGrammarKey key = new TransGrammarKey(labelType, eventType, TransDirection.DIRECT);
                List<TransGrammarEntry> grammars = transGrammar.getTransGrammar(key);
                for (TransGrammarEntry entry : grammars) {
                    performTransfer(subjectNode, objectNode, TransDirection.DIRECT, eventType, labelType, entry.getLabel1(), entry, timestamp);
                    hasTrans = true;
                }
            }
        }
        if (direction == TransDirection.REVERSE || direction == TransDirection.TWOWAY) {
            for (LabelType labelType : objectNode.getLabels().stream().sorted().collect(Collectors.toList())) {
                TransGrammarKey key = new TransGrammarKey(labelType, eventType, TransDirection.REVERSE);
                List<TransGrammarEntry> grammars = transGrammar.getTransGrammar(key);
                for (TransGrammarEntry entry : grammars) {
                    performTransfer(subjectNode, objectNode, TransDirection.REVERSE, eventType, entry.getLabel0(), labelType, entry, timestamp);
                    hasTrans = true;
                }
            }
        }
        return hasTrans;
    }

    private void performTransfer(Node subjectNode, Node objectNode, TransDirection direction, EventType eventType, LabelType subjectLabelType, LabelType objectLabelType, TransGrammarEntry grammar, long timestamp) {
        if (subjectNode instanceof FileNode) {
            return;
        }
        if (direction == TransDirection.DIRECT) {
            if (subjectLabelType == LabelType.PT1 && objectLabelType == LabelType.FT1) {
                // 优化下载的检测 当PT1->FT1 时判断网络事件是不是最近才有的
                ProcessNode processNode = (ProcessNode) subjectNode;
                if (!processNode.getProcess().isDownload(timestamp)) {
                    return;
                }
            }
            if (objectLabelType.equals(LabelType.PT28)) {

                // 优化winword->winword 引起的误报问题
                ProcessNode subjectProcessNode = (ProcessNode) subjectNode;
                ProcessNode objectProcessNode = (ProcessNode) objectNode;
                if (subjectProcessNode.getProcess().getProcessName().equals(objectProcessNode.getProcess().getProcessName())) {
                    return;
                }

            }
            if (objectNode.existLabel(objectLabelType) && eventType != EventType.START_SCRIPT) {
                return;
            }

            // PT22 -[ProcessStart]-> PT21 限制subjectProcessNode 没有证书
            if (objectLabelType.equals(LabelType.PT21) && subjectLabelType.equals(LabelType.PT22) && eventType.equals(EventType.PROCESS_START)) {
                ProcessNode subjectProcessNode = (ProcessNode) subjectNode;
                if (!subjectProcessNode.getLabels().contains(LabelType.PT18)) {
                    return;
                }
            }

            objectNode.addLabel(objectLabelType);
            neo4jClient.addLabel(clientId, subjectNode, objectNode, subjectLabelType, objectLabelType, eventType, timestamp / 1000000L);
            if (objectNode.needsJudgeNow()) {
                judgeNode(objectNode, objectLabelType);
                objectNode.turnOffJudgeNow();
            }
        } else {

            // 被敏感文件传递的标签不做限制，正常的标签只会被传递一个，例如 一个文件有 FT1标签，当一个进程执行File_Read事件时，将会被传递PT3标签，但进程的PT3标签只会被第一个访问的文件传递，以后再访问的FT1标签不会再传递，但敏感文件例外
            boolean isMultiLabel = false;
            if (objectNode instanceof FileNodeV2) {
                ProcessNode processNode = (ProcessNode) subjectNode;
                // 判断访问文件的时间，如果是在进程启动附近时间 ，则不传递 访问敏感文件标签
                if (subjectLabelType == LabelType.PT2 && !(processNode.getProcess().getStartTime() > 0 && (timestamp / 1000000000 - processNode.getProcess().getStartTime() / 1000000000) > 5)) {
                    return;
                }

                if (objectNode.getLabels().contains(LabelType.FT5)) {
                    isMultiLabel = true;
                }
            }

            if (subjectLabelType.equals(LabelType.PT30) || subjectLabelType.equals(LabelType.PT2)) {
                isMultiLabel = true;
            }

            if (!isMultiLabel && subjectNode.existLabel(subjectLabelType)) {
                return;
            }

            subjectNode.addLabel(subjectLabelType);
            neo4jClient.addLabel(clientId, objectNode, subjectNode, objectLabelType, subjectLabelType, eventType, timestamp / 1000000L);
            if (subjectNode.needsJudgeNow()) {
                judgeNode(subjectNode, subjectLabelType);
                subjectNode.turnOffJudgeNow();
            }
        }
    }

    private void judgeNode(Node node, LabelType newLabel) {
        if (node instanceof FileNode) {
            return;
        }

        ProcessNode processNode = (ProcessNode) node;
        Set<LabelType> labels = node.getLabels();
        logger.debug("judge: " + processNode + " " + labels);
        String judgeMode = judgeGrammar.judge(labels);

        Set<LabelType> monitorJudgeLables = node.getLabels().stream()
                .filter(p -> !processNode.checkIfLabelHasBeenMonitorReported(p))
                .collect(Collectors.toSet());

        String monitorJudgeMode = monitorJudgeGrammar.judge(monitorJudgeLables);
        if (!"".equals(judgeMode)) {
            logger.info("judge " + processNode + processNode.getLabels() + " result:" + judgeMode);
            judgeLogger.info("{} {} {} {}", processNode.getUuid(), processNode.getProcess().getFileName(), processNode.getLabels(), judgeMode);
            boolean hasNewPhf = false;
            for (LabelType label : labels) {
                if (LabelType.isPhfLabel(label)) {
                    if (!processNode.checkIfPhfHasBeenReported(label)) {
                        processNode.setPhfToAlreadyReported(label);
                        hasNewPhf = true;
                    }
                }
                // 触发刷新画图,更新敏感命令
                if (newLabel.equals(LabelType.PT12) || newLabel.equals(LabelType.PT30) || newLabel.equals(LabelType.PT22) || newLabel.equals(LabelType.PT2)) {
                    hasNewPhf = true;
                }
            }
            boolean trust = trustList.stream().anyMatch(t -> processNode.getProcess().getProcessName().toLowerCase().contains(t));
            if (hasNewPhf && !trust) {
                judgeLogger.info("report {}", processNode.getUuid());
                String comment = outputResult(node, 1, 1, judgeMode);

                //NetworkActivity.getInstance(clientId).saveIpInfoToJson(processNode.getProcess());

                // 根据ProcessNodeuuid生成事件id,生成画图数据后，根据事件id，更新该事件的画图数据
                String eventId = UUID.nameUUIDFromBytes(String.valueOf(processNode.getUuid()).getBytes()).toString();

                reportToDaemon(processNode, comment, 1, 1, judgeMode, eventId);

                neo4jClient.drawAttackGraph(clientId, processNode.getProcess(), eventId);
                neo4jClient.drawProcessRelationGraph(clientId, processNode.getProcess(), eventId);

                long now = System.currentTimeMillis();
                suspectProcess2lastReportTime.putIfAbsent(processNode.getProcess().getUuid(), now);
                suspectProcess2lastReportTime.putIfAbsent(processNode.getProcess().getUuid(), now);
            }
        }

        if (!"".equals(monitorJudgeMode)) {
            Set<LabelType> monitorJudgeModeLabels = monitorJudgeGrammar.getLabelTypeSetByJudgeMode(monitorJudgeMode);
            for (LabelType label : monitorJudgeModeLabels) {
                processNode.setLabelToAlreadyReportedInMonitor(label);
            }

            logger.info("monitor judge " + processNode + " result:" + monitorJudgeMode);

            String md5MonitorResultKey = MD5.hashKeyForDisk(String.format("%s%s", processNode.getProcess().getProcessName(), monitorJudgeMode));
            if (monitorResult.containsKey(md5MonitorResultKey)) {
                logger.info(String.format("The process %s monitor judge result: %s will not report to daemon. The result was reported in an hour.", processNode.getProcess(), monitorJudgeMode));
                return;
            } else {
                monitorResult.put(md5MonitorResultKey, "");
            }

            String comment = outputResult(node, 1, 1, monitorJudgeMode);
            monitorReportToDaemon(node, comment, 1, 1, monitorJudgeMode);
        }
    }

    public void cancelIfReport(Process process) {
        if (process == null) {
            return;
        }

        if (!suspectProcess2lastReportTime.containsKey(process.getUuid())) {
            return;
        }

        ProcessNode processNode = this.processMap.get(process.getUuid());
        if (processNode == null) {
            return;
        }
        // todo 取消是否入ES
        //reportToDaemon(processNode, "", 0, 0, "CANCEL");
        this.suspectProcess2lastReportTime.remove(process.getUuid());
    }

    public void drawGraph(ProcessNode processNode) {
        String eventId = UUID.nameUUIDFromBytes(String.valueOf(processNode.getUuid()).getBytes()).toString();
        neo4jClient.drawAttackGraph(clientId, processNode.getProcess(), eventId);
        neo4jClient.drawProcessRelationGraph(clientId, processNode.getProcess(), eventId);
    }

    public void findAttackerAndDrawGraph(ProcessNode processNode) {
        Long uuid = processNode.getUuid();
        Set<Long> visitedNodes = new HashSet<>();
        traversal(processNode, visitedNodes);
    }

    private void traversal(ProcessNode processNode, Set<Long> visitedNodes) {
        if (processNode == null) {
            return;
        }
        Long uuid = processNode.getUuid();

        if (!visitedNodes.contains(uuid)) {
            visitedNodes.add(uuid);
        } else {
            return;
        }


        if (suspectProcess2lastReportTime.containsKey(uuid.intValue())) {
            long lastDrawTime = suspectProcess2lastDrawTime.getOrDefault(uuid.intValue(), 0L);
            long now = System.currentTimeMillis();
            long diff = now - lastDrawTime;
            if (lastDrawTime == 0 || diff > 10000) {
                String eventId = UUID.nameUUIDFromBytes(String.valueOf(processNode.getUuid()).getBytes()).toString();
                neo4jClient.drawAttackGraph(clientId, processNode.getProcess(), eventId);
                neo4jClient.drawProcessRelationGraph(clientId, processNode.getProcess(), eventId);
                suspectProcess2lastDrawTime.put(uuid.intValue(), now);
            }
        }

        Set<Process> attackers = ProcessInjection.getInstance(clientId).guessRealProcess(processNode.getProcess());
        if (attackers == null || attackers.isEmpty()) {
            return;
        }

        attackers.forEach(attacker -> {
            ProcessNode attackerProcessNode = getProcessNode(attacker.getUuid());
            traversal(attackerProcessNode, visitedNodes);
        });

    }


    private String outputResult(Node node, double maliciousScore, double confidenceScore, String judgeMode) {
        StringBuilder comment = new StringBuilder();
        StringBuilder result = new StringBuilder();
        String delimiter = "";
        for (LabelType labelType : node.getLabels()) {
            comment.append(delimiter);
            comment.append(labelType);
            delimiter = ",";
        }
        if (node instanceof ProcessNode) {
            ProcessNode processNode = (ProcessNode) node;
            result.append(processNode.getProcess());
        } else {
            FileNode fileNode = (FileNode) node;
            result.append(fileNode.getFilePath());
        }
        result.append(" ");
        result.append(comment);

        try (FileWriter fw = new FileWriter("txt/" + node.getClientId() + "/result_" + judgeMode + ".txt", true)) {
            fw.write(result.toString() + "\n");
        } catch (IOException e) {
            logger.error("fw error", e);
        }

        return comment.toString();
    }

    private void reportToDaemon(ProcessNode processNode, String comment, double maliciousScore, double confidenceScore, String alertMode, String eventId) {
        if (CompilationConfig.DEBUG) {
            return;
        }

        if (alertMode.equals("PowershellStealToken") || alertMode.equals("MimikatzStealToken")) {
            // 偷取明文口令，报到内存攻击
            alertMode = "ReflectiveLoadingAttack";
        }

        if (alertMode.equals("MacroAttack")) {
            // 宏后门检测，报到脚本攻击
            alertMode = "ScriptBasedAttack";
        }

        int uuid = (int) processNode.getUuid();
        ProcessTable processTable = ProcessTable.getInstance(processNode.getClientId());
        Process process = processTable.getProcessByUuid(uuid);

        String networkInfoJson = NetworkActivity.getInstance(clientId).getIpInfoJson(processNode.getProcess());
        Reporter.reportResult(processNode.getClientId(), process, comment, alertMode, networkInfoJson, null, eventId);
    }

    private void monitorReportToDaemon(Node node, String comment, double maliciousScore, double confidenceScore, String alertMode) {
        if (CompilationConfig.DEBUG) {
            return;
        }
        int alertLevel = monitorJudgeMode2AlertLevel.getOrDefault(alertMode, 1);
        ProcessNode processNode = (ProcessNode) node;
        int uuid = (int) processNode.getUuid();
        ProcessTable processTable = ProcessTable.getInstance(node.getClientId());
        Process process = processTable.getProcessByUuid(uuid);

        Reporter.monitorReportResult(node.getClientId(), process, comment, maliciousScore, confidenceScore, alertLevel);
    }
}

