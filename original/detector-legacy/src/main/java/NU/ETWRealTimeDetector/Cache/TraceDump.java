package NU.ETWRealTimeDetector.Cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class TraceDump {

    private static Logger logger = LoggerFactory.getLogger(TraceDump.class);

    private static Map<TraceKey, Long> traceKey2Serial;
    static {
        traceKey2Serial = new HashMap<TraceKey, Long>();
        File dumpProcessedEvent = new File("dumpProcessedEvent/");
        if (!dumpProcessedEvent.exists()) {
            dumpProcessedEvent.mkdir();
        }
    }

    public static void resetSerialNumber(TraceKey traceKey) {
        if (traceKey2Serial.containsKey(traceKey)) {
            traceKey2Serial.put(traceKey, 0L);
        }
    }

}
