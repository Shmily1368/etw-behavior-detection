package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;

public class SensitiveProgram {
    private static final Logger logger = LoggerFactory.getLogger(SensitiveProgram.class);
    private static Map<String, SensitiveProgram> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    public static SensitiveProgram getInstance(String clientId) {
        SensitiveProgram instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new SensitiveProgram(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private static Set<String> sensitivePrograms = new HashSet<>();

    static {
        try (Scanner scanner = new Scanner(new FileReader("signatures/commandline/SensitiveCommandLine"))) {
            while (scanner.hasNextLine()) {
                String commandLine = scanner.nextLine();
                sensitivePrograms.add(commandLine.split(" ")[0]);
            }
        } catch (Exception e) {
            logger.error("scanner error", e);
        }
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private String clientId;
    private Map<Integer, HashSet<String>> processId2SensitivePrograms = new HashMap<>();


    private SensitiveProgram(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    public Process[] addProcessIdAndParentIdAndCommandLineAndFileName(int processId, int parentId, String commandLine, String fileName, long timestamp) {
        // dump start
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("ProcessId", processId);
            arguments.put("ParentId", parentId);
            arguments.put("Cmd", commandLine);
            arguments.put("FileName", fileName);
            dumpEvent.writeToDump("ProcessStart", processId, timestamp, arguments);
        }
        // dump end

        Process childProcess = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        Process parentProcess = processTable.getProcessOrCreateOneIfNotExist(parentId, timestamp);

        // 如果执行敏感程序的是cmd，则将敏感程序记录到cmd的父进程上
        Process parentOrAncestorProcess = parentProcess;
        if (parentProcess.getFileName() != null && parentProcess.getFileName().contains("cmd")) {
            ProcessNode parentProcessNode = DetectionFramework.getInstance(clientId).getProcessMap().get(parentProcess.getUuid());
            if (parentProcessNode != null && parentProcessNode.getParentNode().getProcess().getProcessId() > 0) {
                parentOrAncestorProcess = parentProcessNode.getParentNode().getProcess();
                // todo 如果执行敏感程序的进程是被注入进程，则将敏感程序归到注入进程上
            }
        }

        fileName = fileName.toLowerCase().replace(".exe", "");
        if (fileName.contains("powershell") || fileName.contains("python")) {
            //EventForCS event = new EventForCS(7, clientId, childProcess.getUuid(), processId, timestamp, parentProcess.getUuid(), fileName, commandLine);

            // 标记该进程是一个脚本进程
            LabelForCS label = new LabelForCS(LabelType.PT50, clientId, childProcess.getUuid(), timestamp, "");
            framework.addLabel(label);

            EventForCS event = new EventForCS(EventType.START_SCRIPT, clientId, childProcess, timestamp, parentProcess.getUuid(), fileName, commandLine);
            framework.addEvent(event);
        }

        if (sensitivePrograms.contains(fileName)) {
            HashSet<String> sensitivePrograms = processId2SensitivePrograms.getOrDefault(parentOrAncestorProcess.getProcessId(), new HashSet<>());

            // cmd 特殊处理
            boolean reportCmd = false;
            if (sensitivePrograms.contains("cmd")) {
                reportCmd = fileName.equals("cmd");
            }
            if (!sensitivePrograms.contains(fileName)) {
                sensitivePrograms.add(fileName);
                processId2SensitivePrograms.put(parentOrAncestorProcess.getProcessId(), sensitivePrograms);
                if (reportCmd || sensitivePrograms.size() >= 2) {
                    StringBuilder sb = new StringBuilder();
                    for (String cmd : sensitivePrograms) {
                        sb.append(cmd);
                        sb.append(",");
                    }

                    Set<Process> attackers = ProcessInjection.getInstance(clientId).guessRealProcess(parentOrAncestorProcess);

                    if (attackers == null) {
                        LabelForCS label = new LabelForCS(LabelType.PT12, clientId, parentOrAncestorProcess.getUuid(), timestamp, sb.toString());
                        framework.addLabel(label);
                    } else {
                        LabelForCS label = new LabelForCS(LabelType.PT72, clientId, parentOrAncestorProcess.getUuid(), timestamp, sb.toString());
                        framework.addLabel(label);

                        Process finalParentOrAncestorProcess = parentOrAncestorProcess;
                        attackers.forEach((attacker) -> {
                            ProcessInjection.getInstance(clientId).triggerRemoteThreadPhfEvent(finalParentOrAncestorProcess, attacker, timestamp, null);
                        });
                    }

                    if (TURN_ON_DUMP) {
                        report(parentProcess, timestamp, sb.toString());
                    }
                }
            }
        }

        // 敏感程序上报
        // 敏感程序上报 跟 PT12标签的检测是没有关系的

        return new Process[]{childProcess, parentProcess};
    }

    public void addProcessEnd(int processId) {
        if (processId2SensitivePrograms.containsKey(processId)) {
            processId2SensitivePrograms.remove(processId);
        }
    }

    public Set<String> getSensitiveProgram(int processId) {
        if (processId2SensitivePrograms.containsKey(processId)) {
            return processId2SensitivePrograms.get(processId);
        }

        return null;
    }

    public Map<Integer, HashSet<String>> getProcessId2SensitivePrograms() {
        return this.processId2SensitivePrograms;
    }

    private void report(Process process, long timestamp, String cmds) {
        Map arguments = new HashMap();
        arguments.put("Cmds", cmds);
        dumpEvent.writeToDump("ExecuteSensitiveProgram", process.getProcessId(), timestamp, arguments);
    }
}
