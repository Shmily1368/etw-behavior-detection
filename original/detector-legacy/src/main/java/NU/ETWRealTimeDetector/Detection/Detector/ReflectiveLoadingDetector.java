package NU.ETWRealTimeDetector.Detection.Detector;

import NU.ETWRealTimeDetector.Cache.TraceKey;
import NU.ETWRealTimeDetector.Signature.ApiToInteger;
import NU.ETWRealTimeDetector.SysConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.*;

public class ReflectiveLoadingDetector {
    private static int detectWindowSize = SysConfig.getInteger("ReflectiveLoadingDetectWindowSize", 1000);
    private static int slideWindowSize = SysConfig.getInteger("ReflectiveLoadingSlideWindowSize", 500);
    private static int threshold = SysConfig.getInteger("ReflectiveLoadingThreshold", 50);
    private static Logger logger = LoggerFactory.getLogger(ReflectiveLoadingDetector.class);
    private static int getProcAddress = ApiToInteger.stringToInteger("GetProcAddress");
    private static Set<Integer> keyApis = new HashSet<Integer>(4) {{
        add(ApiToInteger.stringToInteger("VirtualAlloc"));
        add(ApiToInteger.stringToInteger("FlushInstructionCache"));
        add(ApiToInteger.stringToInteger("VirtualProtect"));
        add(ApiToInteger.stringToInteger("VirtualQuery"));
    }};
    static {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("dumpProcessedEvent/reflectiveApi"))) {
            bw.write(String.format("%s %d\n", "VirtualAlloc", ApiToInteger.stringToInteger("VirtualAlloc")));
            bw.write(String.format("%s %d\n", "FlushInstructionCache", ApiToInteger.stringToInteger("FlushInstructionCache")));
            bw.write(String.format("%s %d\n", "VirtualProtect", ApiToInteger.stringToInteger("VirtualProtect")));
            bw.write(String.format("%s %d\n", "VirtualQuery", ApiToInteger.stringToInteger("VirtualQuery")));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void detect(List<Integer> traceToDetect, TraceKey traceKey) {
        if (traceToDetect.size() == 0) {
            return;
        }
        int startIndex = 0;
        JudgingCriteria judgingCriteria = new JudgingCriteria();

        while (startIndex + detectWindowSize <= traceToDetect.size()) {
            List<Integer> detectWindow = traceToDetect.subList(startIndex, startIndex + detectWindowSize);
            Map<Integer, Integer> keyApi2Counts = performDetection(detectWindow, judgingCriteria, traceKey);
            if (judgingCriteria.meetCriteria()) {
                report(traceKey, keyApi2Counts);
                return;
            }
            startIndex += slideWindowSize;
        }
        List<Integer> detectWindow = traceToDetect.subList(startIndex, traceToDetect.size());
        Map<Integer, Integer> keyApi2Counts = performDetection(detectWindow, judgingCriteria, traceKey);
        if (judgingCriteria.meetCriteria()) {
            report(traceKey, keyApi2Counts);
        }
    }

    private static Map<Integer, Integer> performDetection(List<Integer> detectWindow, JudgingCriteria judgingCriteria, TraceKey traceKey) {
        Map<Integer, Integer> keyApi2Counts = new HashMap<>();
        for (Integer api : detectWindow) {
            if (keyApis.contains(api)) {
                int count = keyApi2Counts.getOrDefault(api, 0);
                count++;
                keyApi2Counts.put(api, count);
            }
            if (api == getProcAddress) {
                judgingCriteria.containsGetProcAddress = true;
            }
        }
        if (keyApi2Counts.size() != 0) {
            try (BufferedWriter bw = new BufferedWriter(new FileWriter("dumpProcessedEvent/Reflective", true))) {
                bw.write(traceKey.toString());
                bw.newLine();
                bw.write(keyApi2Counts.toString());
                bw.newLine();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        boolean containsManyKeyApis = true;
        if (keyApi2Counts.size() < 2) {
            containsManyKeyApis = false;
        }
        int goodApis = 0;
        for (int count : keyApi2Counts.values()) {
            if (count >= threshold) {
                goodApis++;
            }
        }
        if (goodApis < 2) {
            containsManyKeyApis = false;
        }
        judgingCriteria.containsManyKeyApis = containsManyKeyApis;
        return keyApi2Counts;
    }

    private static void report(TraceKey traceKey, Map<Integer, Integer> keyApi2Counts) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("dumpProcessedEvent/ReflectiveLoading", true))) {
            bw.write(traceKey.toString());
            bw.newLine();
            bw.write(traceKey.getProcess().toString());
            bw.newLine();
            bw.write(keyApi2Counts.toString());
            bw.newLine();
            bw.newLine();
        } catch (Exception e) {
            logger.error("bw error", e);
        }
    }
}

class JudgingCriteria {
    boolean containsGetProcAddress = false;
    boolean containsManyKeyApis = false;
    boolean meetCriteria() {
        return (containsGetProcAddress && containsManyKeyApis);
    }
}

