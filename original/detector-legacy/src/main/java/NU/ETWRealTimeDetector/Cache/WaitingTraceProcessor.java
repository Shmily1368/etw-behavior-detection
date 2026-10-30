/*
package NU.ETWRealTimeDetector.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

public class WaitingTraceProcessor implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(WaitingTraceProcessor.class);
    private ConcurrentLinkedQueue<ConcurrentMap<TraceKey, TraceCache>> listOfTraceKey2traceCache;

    public WaitingTraceProcessor(ConcurrentLinkedQueue<ConcurrentMap<TraceKey, TraceCache>> listOfTraceKey2traceCache) {
        this.listOfTraceKey2traceCache = listOfTraceKey2traceCache;
    }

    @Override
    public void run() {
        while (true) {
            for (Map<TraceKey, TraceCache> traceCacheMap : listOfTraceKey2traceCache) {
                for (TraceKey traceKey : traceCacheMap.keySet()) {
                    try {
                        TraceCache traceCache = traceCacheMap.get(traceKey);
                        traceCache.checkIfShouldDetect(false);
                    } catch (Exception e) {
                        logger.error("waiting trace processor error", e);
                    }
                }
            }
        }
    }
}
*/
