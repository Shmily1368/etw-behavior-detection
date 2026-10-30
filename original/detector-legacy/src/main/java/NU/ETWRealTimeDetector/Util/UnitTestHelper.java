package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import org.apache.commons.lang3.math.NumberUtils;

import java.util.HashMap;
import java.util.Map;

public class UnitTestHelper {


    public static EventRecord string2EventRecord(String line) {
        int processId = Integer.parseInt(line.split("processId\":")[1].split(",")[0]);
        int threadId = Integer.parseInt(line.split("threadId\":")[1].split(",")[0]);
        long timestamp = Long.parseLong(line.split("timestamp\":")[1].split(",")[0]);
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
        }

        return record;
    }
}
