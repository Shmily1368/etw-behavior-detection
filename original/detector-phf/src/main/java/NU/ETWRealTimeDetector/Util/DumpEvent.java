package NU.ETWRealTimeDetector.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

public class DumpEvent implements IDumper {
    private static final Logger logger = LoggerFactory.getLogger(DumpEvent.class);

    private String clientId;
    private boolean directoryInit = false;
    private Map<String, PrintWriter> fileName2PrintWriter = new HashMap<>();

    public DumpEvent(String clientId) {
        this.clientId = clientId;
    }

    private void initDirectory() {
        File directory = new File(String.format("dumpProcessedEvent/%s", clientId));
        if (!directory.exists()) {
            directory.mkdirs();
        }
    }

    private PrintWriter initDumpWriter(String fileName) {
        if (!directoryInit) {
            initDirectory();
        }
        PrintWriter printWriter = null;
        if (!fileName2PrintWriter.containsKey(fileName)) {
            try {
                printWriter = new PrintWriter(new FileOutputStream(new File(String.format("dumpProcessedEvent/%s/%s", clientId, fileName)), true), true);
                fileName2PrintWriter.put(fileName, printWriter);
                return printWriter;
            } catch (Exception e) {
                logger.info("Create file {} fail!", fileName);
            }
        } else {
            printWriter = fileName2PrintWriter.get(fileName);
        }
        return printWriter;
    }

    @Override
    public void writeToDump(String fileName, int processId, long timestamp, Map arguments) {
        PrintWriter pw = initDumpWriter(fileName);
        pw.print(String.format("%d$$%d", processId, timestamp));
        for (Object key : arguments.keySet()) {
            pw.print(String.format("$$%s:%s", key, arguments.get(key)));
        }
        pw.println();
        pw.flush();
    }
}
