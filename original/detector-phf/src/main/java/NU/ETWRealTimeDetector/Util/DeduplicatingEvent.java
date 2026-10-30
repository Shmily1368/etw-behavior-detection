package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import bloomfilter.CanGenerateHashFrom;
import bloomfilter.mutable.BloomFilter;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class DeduplicatingEvent {
    private String clientId;

    private static Map<String, DeduplicatingEvent> clientId2instance = new HashMap<>();
    private static final int keepTime = SysConfig.getInteger("DeduplicatingBloomFilterKeepTime", 60);
    private static final int length = SysConfig.getInteger("DeduplicatingEventBloomFilterLength", 1000000);
    private static ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private static AtomicLong cleanCount = new AtomicLong(0);
    private List<BloomFilter<byte[]>> bloomFilterList = new ArrayList<>();

    public static synchronized DeduplicatingEvent getInstance(String clientId) {
        DeduplicatingEvent instance = clientId2instance.get(clientId);
        if (instance == null) {
            instance = new DeduplicatingEvent(clientId);
            clientId2instance.put(clientId, instance);
        }
        return instance;
    }

    static {
        timer.scheduleWithFixedDelay(() -> {
            long count = cleanCount.incrementAndGet();
            int index = (int) count % 2;
            clientId2instance.values().forEach(d -> {
                BloomFilter<byte[]> newBloomFilter = BloomFilter.apply(length, 0.01, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
                BloomFilter<byte[]> oldBloomFilter;
                synchronized (d) {
                    oldBloomFilter = d.bloomFilterList.get(index);
                    d.bloomFilterList.set(index, newBloomFilter);
                }
                oldBloomFilter.dispose();
            });
        }, keepTime, keepTime, TimeUnit.SECONDS);
    }

    public DeduplicatingEvent(String clientId) {
        this.clientId = clientId;
        BloomFilter<byte[]> eventFilterA = BloomFilter.apply(length, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
        BloomFilter<byte[]> eventFilterB = BloomFilter.apply(length, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
        bloomFilterList.add(eventFilterA);
        bloomFilterList.add(eventFilterB);
    }

    public static void removeClient(String clientId) {
        DeduplicatingEvent deduplicatingEvent = clientId2instance.get(clientId);
        if (deduplicatingEvent == null) {
            return;
        }
        deduplicatingEvent.destory();
        clientId2instance.remove(clientId);
    }

    private void destory() {
        synchronized (this) {
            bloomFilterList.forEach(bl -> bl.dispose());
        }
    }

    public boolean exist(StringBuilder builder) {
        synchronized (this) {
            BloomFilter<byte[]> filterA = bloomFilterList.get(0);
            byte[] bytes = builder.toString().getBytes();
            boolean exist = filterA.mightContain(bytes);
            if (exist) {
                return true;
            }

            BloomFilter<byte[]> filterB = bloomFilterList.get(1);
            exist = filterB.mightContain(bytes);
            if (!exist) {
                filterA.add(bytes);
                filterB.add(bytes);
            }
            return exist;
        }
    }
}
