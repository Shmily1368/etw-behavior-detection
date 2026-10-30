package NU.ETWRealTimeDetector.ExtraDetectionFactors;


import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;
import java.util.regex.Pattern;

public class PowerShell {
    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);
    private static List<Pattern> patternList = new ArrayList<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);
    private static final boolean POWER_TURN_ON_DUMP = SysConfig.getBoolean("PowerShellDump", false);
    private static Map<String, PowerShell> clientId2Instance = new HashMap<>();

    public static PowerShell getInstance(String clientId) {
        PowerShell powerShell = clientId2Instance.get(clientId);
        if (powerShell == null) {
            powerShell = new PowerShell(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, powerShell);
        return powerShell;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    static {
        try (Scanner scanner = new Scanner(new FileReader("signatures/powershell/MalPowerShell.sig"))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                patternList.add(Pattern.compile(line));
            }
        } catch (Exception e) {
            logger.error("scanner error", e);
        }
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private Map<Process, List<String>> process2PowerShellCommands = new HashMap<>();

    PowerShell(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
    }

    public void checkPowerShellCommand(int processId, long timestamp, String powerShellCommand) {
        if (powerShellCommand.equals("prompt")) {
            return;
        }
        // dump start
        if (POWER_TURN_ON_DUMP || TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("Cmd", powerShellCommand);
            dumpEvent.writeToDump("PowerShell", processId, timestamp, arguments);
        }
        // dump end

//        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
//        String powerShellCommandToDetect = powerShellCommand.toLowerCase();
//        if (process2PowerShellCommands.containsKey(process)) {
//            process2PowerShellCommands.get(process).add(powerShellCommand);
//        } else {
//            List<String> powerShellCommands = new ArrayList<>();
//            powerShellCommands.add(powerShellCommand);
//            process2PowerShellCommands.put(process, powerShellCommands);
//        }
//        for (Pattern pattern : patternList) {
//            Matcher matcher = pattern.matcher(powerShellCommandToDetect);
//            if (matcher.find()) {
//                 TODO: report
//                report(process);
//            }
//        }
    }

    private void report(Process process) {
        /*
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("dumpProcessedEvent/Powershell"))) {
            bw.write(process.toString());
            bw.newLine();
            List<String> commands = process2PowerShellCommands.get(process);
            for (String command : commands) {
                bw.write(command);
                bw.newLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
    }
}
