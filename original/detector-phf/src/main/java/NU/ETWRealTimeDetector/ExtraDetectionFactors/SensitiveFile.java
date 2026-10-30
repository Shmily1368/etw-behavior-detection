package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.FileOperation;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;
import java.util.regex.*;

public class SensitiveFile {
    private static final Logger logger = LoggerFactory.getLogger(SensitiveFile.class);
    private static List<String> sensitiveFileList = new ArrayList<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    private static Map<String, SensitiveFile> clientId2Instance = new HashMap<>();

    public static SensitiveFile getInstance(String clientId) {
        SensitiveFile instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new SensitiveFile(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    static {
        try (Scanner scanner = new Scanner(new FileReader("signatures/SensitiveFile/SensitiveFileList"))) {
            while (scanner.hasNextLine()) {
                sensitiveFileList.add(scanner.nextLine());
            }
        } catch (Exception e) {
            logger.error("scanner error", e);
        }
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private String clientId;

    SensitiveFile(String clientId) {
        framework = DetectionFramework.getInstance(clientId);
        processTable = ProcessTable.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    public Process addFileReadOrWrite(int processId, long timestamp, String fileName, FileOperation operation) {
        // dump start
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("FileName", fileName);
            arguments.put("Op", operation);
            dumpEvent.writeToDump("FileAccess", processId, timestamp, arguments);
        }
        // dump end

        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        fileName = fileName.toLowerCase();
        for (String str : sensitiveFileList) {
            // if (fileName.endsWith(str)) {
            //     // 排除程序启动后立刻加载的ini文件
            //     if (process.getStartTime() > 0 && ((timestamp / 1000000000 - process.getStartTime() / 1000000000) > 5)) {
            //         LabelForCS label = new LabelForCS(LabelType.FT5, clientId, timestamp, fileName);
            //         framework.addLabel(label);
            //         if (TURN_ON_DUMP) {
            //             report(process, timestamp, fileName, operation);
            //         }
            //     }
            // }
            String content = fileName.replaceAll("\\\\", "");
            // String pattern = "c:users.*desktopdesktop.ini";
            boolean isMatch = Pattern.matches(str, content);
            if (isMatch) {
                logger.info("match:" + str);
                // 排除程序启动后立刻加载的ini文件
                if (process.getStartTime() > 0 && ((timestamp / 1000000000 - process.getStartTime() / 1000000000) > 5)) {
                    LabelForCS label = new LabelForCS(LabelType.FT5, clientId, timestamp, fileName);
                    framework.addLabel(label);
                    if (TURN_ON_DUMP) {
                        report(process, timestamp, fileName, operation);
                    }
                }
            }
        }
        return process;
    }

    private void report(Process process, long timestamp, String fileName, FileOperation operation) {
        Map arguments = new HashMap();
        arguments.put("FileName", fileName);
        arguments.put("Op", operation);
        dumpEvent.writeToDump("AccessSensitiveFile", process.getProcessId(), timestamp, arguments);
    }
}
