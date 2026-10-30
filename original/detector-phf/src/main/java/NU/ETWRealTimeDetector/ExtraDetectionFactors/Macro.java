package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import NU.ETWRealTimeDetector.Util.MD5;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.*;
import java.util.stream.Collectors;

public class Macro {
    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);
    private static Map<String, Macro> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    public static Macro getInstance(String clientId) {
        Macro macro = clientId2Instance.get(clientId);
        if (macro == null) {
            macro = new Macro(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, macro);

        return macro;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private ProcessInjection processInjection;
    private IDumper dumpEvent;
    private String clientId;

    public Macro(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        processInjection = ProcessInjection.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        initDirectory(clientId);
        this.clientId = clientId;
    }

    private static Set<String> macroFiles = new HashSet<>();

    static {
        try (Scanner scanner = new Scanner(new FileReader("signatures/MacroFile/MacroFile"))) {
            while (scanner.hasNextLine()) {
                String extension = scanner.nextLine();
                macroFiles.add(extension);
            }
        } catch (Exception e) {
            logger.error("scanner error", e);
        }
    }

    // macroState == 2: has macro
    // macroState == 20: has malicious macro
    public void checkIfMacroMalicious(int processId, int macroState, String macroContent, String fileName, long timestamp) {
        // start dump
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("FileName", fileName);
            arguments.put("MacroState", macroState);
            dumpEvent.writeToDump("Macro", processId, timestamp, arguments);
        }
        // end dump

        // save macroContent
        String macroContentSavedFileName = "";
        if (macroContent != null && !macroContent.isEmpty()) {
            macroContentSavedFileName = saveMacroContent(fileName, macroContent);
        }

        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        if (macroState == 2 || macroState == 20) {
            HashMap<String, String> extend = new HashMap<>();
            extend.put("MacroContentSavedFile", macroContentSavedFileName);
            LabelForCS label = new LabelForCS(LabelType.FT4, clientId, timestamp, fileName, extend);
            framework.addLabel(label);

            // 宏检测结果会延后，有宏检测结果，说明肯定该进程读过这个文件，所以重新触发一次FileRead事件
            EventForCS fileIoReadEvent = new EventForCS(EventType.FILE_READ, clientId, process, timestamp, fileName, "");
            framework.addEvent(fileIoReadEvent);

            // 宏检测结果会延后，宏进程可能已经注入了受害进程，所以重新触发一次 Injection、ProcessStart 事件
            processInjection.reCheck(process, timestamp);

            ProcessNode parentProcessNode = framework.getProcessMap().get(process.getUuid());
            List<Process> childProcessList = parentProcessNode.getChildNodes().stream().map(p -> p.getProcess()).collect(Collectors.toList());

            for (Process childProcess : childProcessList) {
                EventForCS event = new EventForCS(EventType.PROCESS_START, clientId, childProcess, timestamp, process.getUuid(), "", "");
                framework.addEvent(event);
            }
        }
    }

    // 当客户端宏检测不稳定时，可以使用这个方法，通过文件后缀判断包含宏的文件
    public void checkIfMacroFile(String fileName, long timestamp) {
        boolean isMacroFile = macroFiles.stream().anyMatch(m -> fileName.endsWith(m));
        if (!isMacroFile) {
            return;
        }

        LabelForCS label = new LabelForCS(LabelType.FT4, clientId, timestamp, fileName, null);
        framework.addLabel(label);
    }

    private String saveMacroContent(String fileName, String macroContent) {
        String md5MacroContent = MD5.hashKeyForDisk(macroContent);
        String md5FileName = MD5.hashKeyForDisk(fileName);

        String savedFileName = MD5.hashKeyForDisk(md5FileName + md5MacroContent);

        String filePath = Reporter.getMacroContentFilePath(clientId, savedFileName);
        File file = new File(filePath);

        if (file.exists()) {
            return filePath;
        }

        try (PrintWriter printWriter = new PrintWriter(new FileOutputStream(file))) {
            printWriter.write(macroContent);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }

        // report
        Reporter.reportMacro(clientId, fileName, savedFileName);

        return filePath;
    }

    private void initDirectory(String clientId) {
        File directory = new File(String.format("macroContent/%s", clientId));
        if (!directory.exists()) {
            directory.mkdirs();
        }
    }
}
