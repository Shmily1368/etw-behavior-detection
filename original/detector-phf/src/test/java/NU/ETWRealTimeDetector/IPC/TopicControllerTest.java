package NU.ETWRealTimeDetector.IPC;

import NU.ETWRealTimeDetector.SysConfig;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Type;
import java.util.Map;

import static org.junit.Assert.*;

public class TopicControllerTest {
    @Before
    public void setconfig() {
        SysConfig.setInteger("IPCPort", 45555);
    }

    @Test
    public void run() {
        String message = "{action:detectorConfig,honeypot_port:\"4536,7865,8794\"}";
        System.out.println(message);

        Gson gson = new Gson();
        Type type = new TypeToken<Map<String, String>>() {
        }.getType();
        Map<String, String> parsedMessage = null;
        parsedMessage = gson.fromJson(message, type);
        System.out.println(parsedMessage);
    }

    @Test
    public void testRun() {
        String message = "{action:add, topic:dev_dev_detector04_709, clientID:709, offset:8654, honeyPot:1}";
        Gson gson = new Gson();
        Type type = new TypeToken<Map<String, String>>() {
        }.getType();
        Map<String, String> parsedMessage = null;
        parsedMessage = gson.fromJson(message, type);
        System.out.println(parsedMessage);
        Integer honeyPot = 0;
        if (parsedMessage.containsKey("honeyPot")) {
            honeyPot = Integer.valueOf(parsedMessage.get("honeyPot"));
        }
        assertTrue(honeyPot.equals(1));
    }

    @Test
    public void testRun1() {
        TopicController topicController = new TopicController(null, null);
        topicController.run();
    }
}