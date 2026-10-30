/*
package NU.ETWRealTimeDetector.Detection;

import NU.ETWRealTimeDetector.Detection.Detector.LCSDetector;
import NU.ETWRealTimeDetector.Cache.TraceKey;
import NU.ETWRealTimeDetector.Detection.Detector.ReflectiveLoadingDetector;
import NU.ETWRealTimeDetector.Signature.ApiToInteger;
import NU.ETWRealTimeDetector.SysConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.List;

public class DetectionTask implements Runnable {
    private TraceKey traceKey;
    private List<Integer> traceToDetect;
    private long firstApiTimestamp;

    private static final Logger logger = LoggerFactory.getLogger(DetectionTask.class);

    public DetectionTask(List<Integer> traceToDetect, TraceKey traceKey, Long firstApiTimestamp) {
        this.traceToDetect = traceToDetect;
        this.traceKey = traceKey;
        this.firstApiTimestamp = firstApiTimestamp != null ? firstApiTimestamp : 0;
    }

    @Override
    public void run() {
        if (traceToDetect.size() == 0) {
            return;
        }
        LCSDetector.detect(traceToDetect, this.traceKey, firstApiTimestamp);
        ReflectiveLoadingDetector.detect(traceToDetect, this.traceKey);
        logger.info("detect {}", traceKey.toString());
    }
}
*/
