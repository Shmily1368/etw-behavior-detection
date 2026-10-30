package NU.ETWRealTimeDetector.Framework;

import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import org.apache.commons.lang3.math.NumberUtils;
import org.junit.Test;

import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class OfflineReader {
    @Test
    public void read() {
        Neo4jClient neo4jClient = Neo4jClient.getInstance();
        String clientId = "weihaoPC";
        System.out.println("");
        MessageProcessor processor = new MessageProcessor(null);
        processor.setCurrent(clientId);
        try (Scanner scanner = new Scanner(new FileReader("yihuan.out"))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                int processId = Integer.parseInt(line.split("processID\":")[1].split(",")[0]);
                int threadId = Integer.parseInt(line.split("threadID\":")[1].split(",")[0]);
                long timestamp = Long.parseLong(line.split("TimeStamp\":")[1].split(",")[0]);

                EventRecord record;
                if (line.contains("CallStack")) {
                    String callstack = line.split("CallStack\":\"")[1].split(",")[0];
                    record = new EventRecord(EtwEventType.Callstack, processId, threadId, timestamp);
                    record.callstack = callstack;

                } else {
                    EtwEventType eventType = EtwEventType.valueOf(line.split("EventName\":\"")[1].split("\"")[0]);
                    record = new EventRecord(eventType, processId, threadId, timestamp);
                    String argumentsInString = line.split("arguments\":\\{")[1].split("\\}\\}")[0];
                    if (argumentsInString.startsWith("\"")) {
                        argumentsInString = argumentsInString.substring(1, argumentsInString.length());
                    }
                    String[] arguments = argumentsInString.split(",\"");

                    Map argumentMap = new HashMap();
                    for (String arg : arguments) {
                        String[] split = arg.split("\":", 2);
                        String key = split[0];
                        String value = split[1];
                        if (value.startsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        if (NumberUtils.isNumber(value)) {
                            if (value.length() > 10) {
                                value = "-1";
                            }
                            argumentMap.put(key, Long.parseLong(value));
                        } else {
                            argumentMap.put(key, value);
                        }
                        System.out.println(value);
                    }
                    record.argument = argumentMap;
                }
                processor.distributeRecord(record);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        while (1 == 1) {
            try {
                Thread.sleep(1000);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
