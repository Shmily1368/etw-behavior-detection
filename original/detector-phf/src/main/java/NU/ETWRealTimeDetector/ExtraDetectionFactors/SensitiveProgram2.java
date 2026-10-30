package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Pojo.SensitiveProgram2Info;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;

public class SensitiveProgram2 {
    private static final Logger logger = LoggerFactory.getLogger(SensitiveProgram2.class);
    private static Map<String, SensitiveProgram2> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    public static SensitiveProgram2 getInstance(String clientId) {
        SensitiveProgram2 instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new SensitiveProgram2(clientId);
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
                if (commandLine.equals("cmd")) {
                    continue;
                }
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
    //private Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitivePrograms = new HashMap<>();
    private Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitivePrograms = new HashMap<>();

    private SensitiveProgram2(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    /*
    检测ProcessStart事件的commandline参数是否包含敏感程序，如果执行了敏感程序，直接将该进程的父进程上报给webportal，这个敏感程序跟PT12的检测稍有区别
     */
    public void checkSensitiveProgram(int processId, int parentId, String commandLine, String fileName, long timestamp) {

        Process parentProcess = processTable.getProcessOrCreateOneIfNotExist(parentId, timestamp);

        fileName = fileName.toLowerCase().replace(".exe", "");

        // ProcessStart时 检测是否为敏感程序，ImageLoad时画进程关系图
        if (sensitivePrograms.contains(fileName)) {

            HashMap<String, SensitiveProgram2Info> sensitiveProgram2Infos = processId2SensitivePrograms.getOrDefault(parentProcess.getProcessId(), new HashMap<>());
            processId2SensitivePrograms.putIfAbsent(parentProcess.getProcessId(), sensitiveProgram2Infos);

            SensitiveProgram2Info info = sensitiveProgram2Infos.get(fileName);
            if (info == null) {
                info = new SensitiveProgram2Info();
                sensitiveProgram2Infos.put(fileName, info);
            }

            info.increment();

            if (TURN_ON_DUMP) {
                report(parentProcess, timestamp, String.format("pid_%d_%s_%s", processId, commandLine, fileName));
            }
        }
    }

    public void addProcessEnd(int processId) {
        // 测测中发现反弹shell 执行敏感命令，是先启动一个cmd，通过cmd再执行敏感命令，但cmd会很快结束，导致敏感命令没有上报
        if (processId2SensitivePrograms.containsKey(processId)) {
            processId2SensitivePrograms.remove(processId);
        }
    }


    public HashMap<String, SensitiveProgram2Info> getSensitiveProgram(int processId) {
        return processId2SensitivePrograms.get(processId);
    }

    private void report(Process process, long timestamp, String cmd) {
        Map arguments = new HashMap();
        arguments.put("Cmd", cmd);
        dumpEvent.writeToDump("ExecuteSensitiveProgram2", process.getProcessId(), timestamp, arguments);
    }

    public Map<Integer, HashMap<String, SensitiveProgram2Info>> getProcessId2SensitivePrograms() {
        return this.processId2SensitivePrograms;
    }
}

