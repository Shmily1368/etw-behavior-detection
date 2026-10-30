package NU.ETWRealTimeDetector.EventRecord;

import NU.ETWRealTimeDetector.Cache.TraceKey;
import NU.ETWRealTimeDetector.SysConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public class DumpAPI {
    private static Map<TraceKey, PrintWriter> traceKey2PrintWriter = new LinkedHashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(DumpAPI.class);

    static {
        File file = new File("dumpProcessedEvent/traces/");
        if (!file.exists()) {
            file.mkdirs();
        }
    }

    public static void dumpApi(TraceKey traceKey, String api) {
        try {
            PrintWriter pw = traceKey2PrintWriter.get(traceKey);
            if (pw == null) {
                pw = new PrintWriter(new FileOutputStream(String.format("dumpProcessedEvent/traces/%s", traceKey), true));
                traceKey2PrintWriter.put(traceKey, pw);
                if (traceKey2PrintWriter.size() > 10) {
                    Iterator it = traceKey2PrintWriter.entrySet().iterator();
                    it.next();
                    it.remove();
                }
            }
            pw.println(api);
            pw.flush();
        } catch (Exception e) {
            logger.error("pw error", e);
        }
    }

}
