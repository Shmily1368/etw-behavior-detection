/*
package NU.ETWRealTimeDetector.Cache;

import NU.ETWRealTimeDetector.Detection.*;
import NU.ETWRealTimeDetector.SysConfig;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class TraceCache {
    private static int detectWindowSize = SysConfig.getInteger("CacheWindowSize", 10000);
    private static int slideWindowSize = SysConfig.getInteger("SlideWindowSize", 3000);
    private static int waitTimeMillis = SysConfig.getInteger("WaitTimeMillis", 60000);
    private static final Logger logger = LoggerFactory.getLogger(TraceCache.class);

    // must use concurrent list, since KafkaConsumer and WaitingTraceProcessor may access it simultaneously
    private ConcurrentLinkedQueue<Integer> cache = new ConcurrentLinkedQueue<>();
    private AtomicInteger cacheSize = new AtomicInteger(0);
    private TraceKey traceKey;
    private long lastDetectTime = System.currentTimeMillis();


    private ConcurrentLinkedQueue<Long> firstApiTimestamp = new ConcurrentLinkedQueue<>();

    public TraceCache(TraceKey traceKey) {
        this.traceKey = traceKey;
        logger.info("TraceCache of {} created", traceKey);
    }

    public void insertApi(Integer api, boolean forceDetect, long timestamp) {
        if (firstApiTimestamp.size() == 0) {
            firstApiTimestamp.add(timestamp);
        }
        if (api != null) {
            cache.add(api);
            cacheSize.incrementAndGet();
        }
        checkIfShouldDetect(forceDetect);
    }

    public synchronized void checkIfShouldDetect(boolean forceDetect) {
        long currentTimeMillis = System.currentTimeMillis();
        // if already cached more than 1000 traces, perform detection
        if (cacheSize.get() >= detectWindowSize
                || currentTimeMillis - lastDetectTime > waitTimeMillis && !cache.isEmpty()
                || forceDetect) {
            lastDetectTime = currentTimeMillis;
            List<Integer> traceToDetect = Lists.newArrayList(cache.iterator());
            DetectionTask detectionTask = new DetectionTask(traceToDetect, traceKey, firstApiTimestamp.poll());
            DetectionThreadPool.execute(detectionTask);
            for (int i = 0; i < slideWindowSize; i++) {
                if (cache.poll() != null) {
                    cacheSize.decrementAndGet();
                }
            }
        }
    }
}
*/
