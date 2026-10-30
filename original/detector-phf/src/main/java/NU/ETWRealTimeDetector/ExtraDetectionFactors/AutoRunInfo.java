package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;
import java.util.stream.Collectors;


public class AutoRunInfo {
    private static final Logger logger = LoggerFactory.getLogger(AutoRunInfo.class);
    private static Map<String, AutoRunInfo> clientId2Instance = new HashMap<>();

    private String clientId;
    private DetectionFramework framework;
    private ProcessTable processTable;

    private List<String> autoRunFiles = new ArrayList<>();

    private static List<String> excludeAutoRunFiles = new ArrayList<>();

    static {
        try (Scanner scanner = new Scanner(new FileReader("signatures/AutoRunInfo/ExcludeAutoRunFiles"))) {
            while (scanner.hasNextLine()) {
                excludeAutoRunFiles.add(scanner.nextLine());
            }
        } catch (Exception e) {
            logger.error("scanner error", e);
        }
    }

    public AutoRunInfo(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        this.clientId = clientId;
    }

    public static AutoRunInfo getInstance(String clientId) {
        AutoRunInfo autoRunInfo = clientId2Instance.get(clientId);
        if (autoRunInfo == null) {
            autoRunInfo = new AutoRunInfo(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, autoRunInfo);
        return autoRunInfo;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    public void processAutoRunInfo(String files) {
        if (files == null || files.isEmpty())
            return;

        autoRunFiles = Arrays.asList(files.split("\\|"));
        // 排除系统默认启动的进程，否则所有进程都成了开机自启动进程
        autoRunFiles = autoRunFiles.stream().filter(auto -> !excludeAutoRunFiles.contains(auto)).collect(Collectors.toList());
        processTable.getUuid2Process()
                .values()
                .stream()
                .filter(process -> process.getEndTime() == 0)
                .filter(process -> autoRunFiles.contains(process.getProcessName().toLowerCase()))
                .forEach(process -> {
                    LabelForCS label = new LabelForCS(LabelType.PT100, clientId, process.getUuid(), process.getStartTime(), "");
                    framework.addLabel(label);
                });

    }

    /**
     * 判断进程是否是开机自启动程序
     *
     * @param process
     */
    public void detectAutoRunProcess(Process process) {
        if (autoRunFiles.contains(process.getProcessName().toLowerCase())) {
            LabelForCS label = new LabelForCS(LabelType.PT100, clientId, process.getUuid(), process.getStartTime(), "");
            framework.addLabel(label);
        }
    }
}
