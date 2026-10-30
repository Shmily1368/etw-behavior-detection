package NU.ETWRealTimeDetector.Framework;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.ThreatIntelligence;
import NU.ETWRealTimeDetector.Framework.Node.filenode.FileNodeManager;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.ShutdownManager;
import org.apache.commons.lang3.math.NumberUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.FileReader;
import java.util.*;

public class OfflineReaderDetector {
    static int i = 1;
    static String line = "";
    static boolean run = true;

    @Before
    public void setConfig() {
        SysConfig.setInteger("ProcessRetentionTime", 1);
        SysConfig.setString("Neo4jCleanPolicy", "EveryMinute");
        SysConfig.setBoolean("EnableNeo4j", true);
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setInteger("ModuleSwitch", 4);
        SysConfig.setString("IllustratorTopic", "illustrator_local_1229");
        SysConfig.setString("ExcludeExtensionOfDownloadFile", "ini,mdb,db,lnk,db-journal,dat,list,pyc,library-ms");
        CompilationConfig.DEBUG = true;
        //new ShutdownManager().run();
        FileNodeManager.init();
        //ThreatIntelligence.init();

        MessageProcessor.honyPotList.put("weihaoPC", 1);
        MessageProcessor.portList.add(3553);
        MessageProcessor.portList.add(3554);
        MessageProcessor.portList.add(8080);
        MessageProcessor.portList.add(8000);
        // chrome.exe
        MessageProcessor.whiteAppList.add(-1510770530);

        // kafkatool.exe
        MessageProcessor.whiteAppList.add(-64929310);

        MessageProcessor.intranet_mode = false;

        Reporter.init();
    }

    @Test
    public void read() {
        Neo4jClient neo4jClient = Neo4jClient.getInstance();

        String clientId = "weihaoPC";
        System.out.println("");
        MessageProcessor processor = new MessageProcessor(null);
        processor.setCurrent(clientId);

        List<Integer> breakPointList = new ArrayList<>();

        /*
        breakPointList.add(173165);// 第一次ProcessDCStart 对应的 VisibleWindowInfo
        breakPointList.add(177495);// 第一次ProcessDCStart

        breakPointList.add(242911);// 第二次ProcessDCStart 对应的 VisibleWindowInfo
        breakPointList.add(247340);// 第二次ProcessDCStart

        breakPointList.add(279415);// 报错 null
        breakPointList.add(292140);// VisibleWindowInfo
        breakPointList.add(296368);// ProcessDCStart
        * */
        //breakPointList.add(43573); // ProcessStart  6572
        breakPointList.add(65156); // 6572-> ThreadStart 2952

        try (Scanner scanner = new Scanner(new FileReader("outputtest.json"))) {
            while (run && scanner.hasNextLine()) {
                line = scanner.nextLine();
                if (i % 10000 == 0) {
                    System.out.println(i);
                }
                //Thread.sleep(10);

                if (breakPointList.contains(i)) {
                    System.out.println(i);
                }
                i++;
                int processId = Integer.parseInt(line.split("processId\":")[1].split(",")[0]);
                int threadId = Integer.parseInt(line.split("threadId\":")[1].split(",")[0]);
                long timestamp = Long.parseLong(line.split("timestamp\":")[1].split(",")[0]);

                if (line.contains("RuleIdentifier")) {
                    continue;
                }

                EventRecord record;
                if (line.contains("Callstack")) {
                    String callstack = line.split("callstack\":\"")[1].split("\",")[0];
                    record = new EventRecord(EtwEventType.Callstack, processId, threadId, timestamp);
                    record.callstack = callstack;

                } else {
                    EtwEventType eventType = EtwEventType.valueOf(line.split("eventName\":\"")[1].split("\"")[0]);
                    record = new EventRecord(eventType, processId, threadId, timestamp);
                    if (line.split("arguments\":\\{")[1].split("\\}\\}").length == 0) {
                        //continue;
                        System.out.println(line);
                    }
                    String argumentsInString = line.split("arguments\":\\{")[1];
                    argumentsInString = argumentsInString.substring(0, argumentsInString.length() - 2);
                    if (argumentsInString.startsWith("\"")) {
                        argumentsInString = argumentsInString.substring(1, argumentsInString.length());
                    }
                    String[] arguments = argumentsInString.split(",\"");

                    Map argumentMap = new HashMap();
                    for (String arg : arguments) {
                        String[] split = arg.split("\":", 2);
                        if (split.length < 2)
                            continue;
                        String key = split[0];
                        String value = split[1];
                        if (value.startsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        if (NumberUtils.isNumber(value) && !value.contains("x")) {
                            if (value.length() > 10) {
                                value = "-1";
                            }
                            argumentMap.put(key, Long.parseLong(value));
                        } else {
                            argumentMap.put(key, value);
                        }
                        //System.out.println(value);
                    }
                    record.argument = argumentMap;
                }


                if (processor.exist(record)) {
                    continue;
                }
                processor.distributeRecord(record);

            }
        } catch (Exception e) {
            System.out.println(i);
            System.out.println(line);
            System.out.println(e.getMessage());
        }


        while (true) {
            try {
                Thread.sleep(1000);
                System.out.println("over");
                System.out.println("add to neo4j task count:" + Neo4jClient.getInstance().counter.get());
                System.out.println("add to neo4j task addFileNode count:" + Neo4jClient.getInstance().fileNodeCounter.get());
                System.out.println("add to neo4j task addProcessNode count:" + Neo4jClient.getInstance().processNodeCounter.get());
                System.out.println("add to neo4j task addProcessRelation count:" + Neo4jClient.getInstance().processRelationCounter.get());
                System.out.println("add to neo4j task addDeleteNodeRelation count:" + Neo4jClient.getInstance().deleteNodeCounter.get());
                System.out.println("add to neo4j task addLabel count:" + Neo4jClient.getInstance().addLabelCounter.get());
                System.out.println("add to neo4j task addProperty count:" + Neo4jClient.getInstance().addPropertyCounter.get());
                System.out.println("add to neo4j task renameFile count:" + Neo4jClient.getInstance().renameFileCounter.get());
                System.out.println("add to neo4j task updateFileName count:" + Neo4jClient.getInstance().updateFileCounter.get());
                System.out.println("add to neo4j task updateProcessNode count:" + Neo4jClient.getInstance().updateProcessNodeCounter.get());

                ProcessTable processTable = ProcessTable.getInstance(clientId);
                Map<Integer, Process> uuid2Process = processTable.getUuid2Process();

                long liveProcessCount = uuid2Process.values().stream().filter(p -> p.getEndTime() == 0).count();
                long diedProcessCount = uuid2Process.values().stream().filter(p -> p.getEndTime() != 0).count();

                Optional<Long> latestProcessStartTime = uuid2Process.values()
                        .stream()
                        .map(Process::getStartTime)
                        .reduce(Long::max);

                System.out.println("ProcessTable process total :" + uuid2Process.size() + " liveProcessCount:" + liveProcessCount + " diedProcessCount:" + diedProcessCount);

                if (latestProcessStartTime.isPresent()) {
                    System.out.println("latest Process StartTime:" + latestProcessStartTime.get() / 1000000);
                    diedProcessCount = uuid2Process.values()
                            .stream()
                            .filter(p -> p.getEndTime() > (latestProcessStartTime.get() / 1000000) - 30000)
                            .count();
                    System.out.println("End threads over 30 minutes ：" + diedProcessCount);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

    }
}
