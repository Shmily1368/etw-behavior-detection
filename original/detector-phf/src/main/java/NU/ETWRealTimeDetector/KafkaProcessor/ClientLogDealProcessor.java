package NU.ETWRealTimeDetector.KafkaProcessor;
import NU.ETWRealTimeDetector.EventRule.CheckRule;
import NU.ETWRealTimeDetector.EventRule.pojo.RuleCacheDict;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.KafkaProcessor.Threat.Threat;
import NU.ETWRealTimeDetector.SysConfig;
import com.alibaba.fastjson.JSON;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class ClientLogDealProcessor extends Thread {

    private LinkedBlockingQueue<Map<String, Object>> upstream;

    public ClientLogDealProcessor(LinkedBlockingQueue<Map<String, Object>> upstream) {
        this.upstream = upstream;
    }

    private static final String eventTopic = SysConfig.getString("EventTopic", "event");

    private static final Logger logger = LoggerFactory.getLogger("ClientLogDealProcessor");

    @Override
    public void run() {
        AtomicInteger num = new AtomicInteger();
        while (true) {
            try {
                Map<String, Object> clientLogMap = upstream.take();
                process(clientLogMap);
                num.incrementAndGet();
                if (num.get() % 10000 == 0) {
                    logger.info(Thread.currentThread().getName()+":"+upstream.size());
                    logger.info((System.currentTimeMillis() + "clientLogMap:" + num));
                }

            } catch (Exception e) {
                logger.error("interrupted", e);
            }
        }
    }

    public void process(Map<String, Object> map) {
        try {
            // 威胁情报
            Threat.check(map);
        } catch (Exception e) {
            logger.error("threat process error", e);
        }

        try {
            // 事件规则检测
            RuleCacheDict dict = CheckRule.check(map);
            if (dict != null) {
                String eventStr = CheckRule.createEvent(dict);
                if (StringUtils.isNotEmpty(eventStr)) {
                    Reporter.reportEventToKafka(eventTopic, eventStr);
                }
            }
        } catch (Exception e) {
            logger.error("log map :"+ JSON.toJSONString(map));
            logger.error("event rule process error"+e);
        }
    }

}
