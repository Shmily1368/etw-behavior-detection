package NU.ETWRealTimeDetector.KafkaProcessor;


import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class CountingEvent {
    private static ConcurrentHashMap<String, AtomicLong> counterMap = new ConcurrentHashMap<>();

    public static AtomicLong getCounter(String clientId, String countType) {
        String key = String.format("%s%s", clientId, countType);
        if (!counterMap.containsKey(key)) {
            counterMap.put(key, new AtomicLong());
        }
        return counterMap.get(key);
    }
}
