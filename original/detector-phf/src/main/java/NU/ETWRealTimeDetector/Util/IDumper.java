package NU.ETWRealTimeDetector.Util;

import java.util.Map;

public interface IDumper {
    void writeToDump(String fileName, int processId, long timestamp, Map arguments);
}
