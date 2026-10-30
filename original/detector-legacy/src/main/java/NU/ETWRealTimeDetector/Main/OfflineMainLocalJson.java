package NU.ETWRealTimeDetector.Main;

import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import com.google.common.base.Splitter;
import org.apache.commons.lang3.math.NumberUtils;

import java.io.*;
import java.util.*;

public class OfflineMainLocalJson {
    public static void main(String[] args) throws Exception {
        MessageProcessor messageProcessor = new MessageProcessor(null);
        //int clientCount = Integer.parseInt(args[0]);
        long start = System.currentTimeMillis();
        int milestone = 100000;

        if (new File("Config").exists()) {
            try (Scanner scanner = new Scanner(new FileReader("Config"))) {
                String line = scanner.nextLine();
                milestone = Integer.parseInt(line);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        BufferedWriter bw = new BufferedWriter(new FileWriter("Memory"));
        DetectionFramework framework = DetectionFramework.getInstance("test");

        //int processorCount = clientCount / 10;

        //List<MessageProcessor> processors = new ArrayList<>();
        Map<MessageProcessor, List<String>> processor2ClientIds = new HashMap<>();
        List<String> allClientIds = new ArrayList<>();
//
        /*
        for (int i = 0; i < processorCount; i++) {
            MessageProcessor processor = new MessageProcessor(null);
            processors.add(processor);
            List<String> clientIds = new ArrayList<>();
            processor2ClientIds.put(processor, clientIds);
            for (int j = 0; j < 10; j++) {
                String clientId = "Client" + i + j;
                clientIds.add(clientId);
                allClientIds.add(clientId);
            }
        }
        */

        System.out.println("");
        long lineCount = 0l;
        long timestamp1 = System.currentTimeMillis();
        int currentMillion = 0;
        try (BufferedReader br = new BufferedReader(new FileReader("attack.out"))) {
            String line;
            while ((line = br.readLine()) != null) {
                lineCount++;
                if (lineCount % milestone == 0) {
                    /*
                    for (String clientId : allClientIds) {
                        framework.removeRecentlyNotUsedFileNodes(clientId);
                    }
                    framework.setCurrentMillion(currentMillion++);
                    */
                    //framework.outputAddEventCount();

                    long currentTimestamp = System.currentTimeMillis();
                    System.out.println("============================================" + lineCount + "==================================================" + (currentTimestamp - timestamp1) / 1000 + "s");
                    timestamp1 = currentTimestamp;
                    System.gc();
                    long memory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
                    bw.write(memory + "\n");
                    bw.flush();
                }

                int startIndex = line.indexOf("processID\":") + 11;
                int endIndex = line.indexOf(",", startIndex);

                int processId = Integer.parseInt(line.substring(startIndex, endIndex));


                startIndex = line.indexOf("threadID\":") + 10;
                endIndex = line.indexOf(",", startIndex);


                int threadId = Integer.parseInt(line.substring(startIndex, endIndex));


                startIndex = line.indexOf("TimeStamp\":") + 11;
                endIndex = line.indexOf(",", startIndex);
                long timestamp = Long.parseLong(line.substring(startIndex, endIndex));

                EventRecord record;
                if (line.contains("CallStack")) {
                    startIndex = line.indexOf("CallStack\":\"") + 12;
                    endIndex = line.indexOf("\"", startIndex);
                    String callstack = line.substring(startIndex, endIndex);
                    record = new EventRecord(EtwEventType.Callstack, processId, threadId, timestamp);
                    record.callstack = callstack;
                } else {

                    startIndex = line.indexOf("EventName\":\"") + 12;
                    endIndex = line.indexOf("\"", startIndex);
                    EtwEventType eventType = EtwEventType.valueOf(line.substring(startIndex, endIndex));
                    record = new EventRecord(eventType, processId, threadId, timestamp);

                    startIndex = line.indexOf("arguments\":{") + 13;
                    endIndex = line.indexOf("}}", startIndex);


                    String argumentsInString = line.substring(startIndex, endIndex);
                    //String[] arguments = argumentsInString.split("\",\"");
                    Iterable<String> arguments = Splitter.on(",\"").split(argumentsInString);

                    Map argumentMap = new HashMap();
                    try {
                        for (String arg : arguments) {
                            startIndex = arg.indexOf("\":");
                            if (startIndex == -1) {
                                System.out.println(lineCount);
                                continue;
                            }
                            String key = arg.substring(0, startIndex);
                            String value = arg.substring(startIndex + 2, arg.length());
                            if (value.startsWith("\"")) {
                                value = value.substring(1);
                            }
                            if (value.endsWith("\"")) {
                                value = value.substring(0, value.length() - 1);
                            }
                            if (NumberUtils.isNumber(value)) {
                                if (value.length() > 10) {
                                    value = "-1";
                                }
                                argumentMap.put(key, Long.parseLong(value));
                            } else {
                                argumentMap.put(key, value);
                            }
                        }
                        record.argument = argumentMap;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                /*
                for (MessageProcessor processor : processors) {
                    List<String> clientIds = processor2ClientIds.get(processor);
                    for (String clientId : clientIds) {
                        processor.setCurrent(clientId);
                        processor.distributeRecord(record);
                    }
                }
                */
                messageProcessor.setCurrent("weihaoPC");
                messageProcessor.distributeRecord(record);
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(lineCount);
        }

        bw.close();
        System.out.println("DONE");
        System.out.println(System.currentTimeMillis() - start);
        while (true) {
            Thread.sleep(1000);
        }
        //framework.outputLabelCount();
    }
}
