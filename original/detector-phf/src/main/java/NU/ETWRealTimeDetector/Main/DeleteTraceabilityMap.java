package NU.ETWRealTimeDetector.Main;

import NU.ETWRealTimeDetector.KafkaProcessor.TraceabilityMapProcessor;
import NU.ETWRealTimeDetector.SysConfig;

import java.io.IOException;

/**
 * @author lisq
 * @date 2022/2/7 11:40 上午
 */
public class DeleteTraceabilityMap {
    public static void main(String[] args) throws Exception {
        long startTime = System.currentTimeMillis();
        config();
        TraceabilityMapProcessor.delRedisOldData();
        long endTime = System.currentTimeMillis();
        long s = (endTime - startTime) / 1000;
        System.out.printf("删除成功用时%s秒%n", s);
    }

    public static void config() {
        try {
            SysConfig.load("DebugConfig.xml");
        } catch (IOException e) {
            e.printStackTrace();
        }
        SysConfig.setString("RedisPassword", "");
        SysConfig.setString("RedisHost", "127.0.0.1");
    }
}
