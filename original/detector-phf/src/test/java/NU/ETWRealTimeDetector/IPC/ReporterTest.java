package NU.ETWRealTimeDetector.IPC;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.Test;

import java.lang.reflect.Type;
import java.util.*;

import static org.junit.Assert.*;

public class ReporterTest {

    @Test
    public void reportExternalIp() {
        HashMap<String, Object> params = new HashMap<>();
        params.put("action", "report_network");

        List<HashMap<String, String>> list = new ArrayList<>();
        HashMap<String, String> map1 = new HashMap<>();
        map1.put("a", "a");
        map1.put("b", "b");
        map1.put("c", "c");

        HashMap<String, String> map2 = new HashMap<>();
        map2.put("a", "a");
        map2.put("b", "b");
        map2.put("c", "c");

        HashMap<String, String> map3 = new HashMap<>();
        map3.put("a", "a");
        map3.put("b", "b");
        map3.put("c", "c");

        list.add(map1);
        list.add(map2);
        list.add(map3);

        params.put("data", list);
        Gson gson = new Gson();
        String json = gson.toJson(params);
        System.out.printf(json);

        List<String> ips = new ArrayList<>();
        ips.add("127.0.0.1");
        ips.add("127.0.0.1");
        ips.add("127.0.0.1");

        HashMap<String, Object> params1 = new HashMap<>();
        params1.put("action", "report_network");
        params1.put("ipwitelist", ips);

        String json1 = gson.toJson(params1);

        Type type = new TypeToken<Map<String, Object>>() {
        }.getType();
        Map<String, Object> parsedMessage = null;
        parsedMessage = gson.fromJson(json1, type);

        Set<String> ll = (Set<String>) parsedMessage.get("ipwitelist");
        assertFalse(ll.isEmpty());


    }
}