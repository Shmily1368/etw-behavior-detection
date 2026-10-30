package NU.ETWRealTimeDetector.Detection;

import NU.ETWRealTimeDetector.SysConfig;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class DetectionThreadPool {
    private static int threadPoolSize;
    //private static ConcurrentLinkedQueue<int[][]> scorePool = new ConcurrentLinkedQueue<int[][]>();
    private static LinkedBlockingQueue<int[][]> scoreArrayPool = new LinkedBlockingQueue<>();
    static {
        threadPoolSize = SysConfig.getInteger("ThreadPoolSize", 30);
        for (int i = 0; i < threadPoolSize; i++) {
            scoreArrayPool.add(new int[300][12000]);
        }
    }
    //private static ExecutorService fixedThreadPool = Executors.newFixedThreadPool(threadPoolSize);
    //private static ExecutorService cachedThreadPool = Executors.newCachedThreadPool();
    public static ExecutorService fixedThreadPool = Executors.newFixedThreadPool(threadPoolSize);

    public static void execute(Runnable r) {
        fixedThreadPool.execute(r);
    }

    public static int[][] getScoreArray() {
        //return new int[300][10500];
        return scoreArrayPool.poll();
    }

    public static void returnScoreArray(int[][] scoreArray) {
        scoreArrayPool.add(scoreArray);
    }

    public static void shutdown() {
        fixedThreadPool.shutdown();
    }
}
