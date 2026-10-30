package NU.ETWRealTimeDetector.Signature;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiToInteger {
    private static Map<String, Integer> apiToInteger = new HashMap<>();
    private static Map<Integer, String> integerToApi = new HashMap<>();
    private static int index = 0;
    public static void addAPI(String api) {
        if (!apiToInteger.containsKey(api)) {
            apiToInteger.put(api, index);
            integerToApi.put(index++, api);
        }
    }

    public static Integer stringToInteger(String api) {
        int result =  apiToInteger.getOrDefault(api, -1);
        if (result == -1) {
            addAPI(api);
        }
        result = apiToInteger.get(api);
        return result;
    }
    public static String integerToString(Integer api) {
        return integerToApi.getOrDefault(api, "unknown");
    }

    public static List<Integer> stringListToIntegerList(List<String> stringList) {
        List<Integer> result = new ArrayList<>(stringList.size());
        for (String str : stringList) {
            int apiInInt = stringToInteger(str);
            if (apiInInt != -1) {
                result.add(apiInInt);
            }
        }
        return result;
    }

    public static List<String> integerListToStringList(List<Integer> integerList) {
        List<String> result = new ArrayList<>(integerList.size());
        for (Integer integer : integerList) {
            String apiInString = integerToString(integer);
            if (!"unknown".equals(apiInString)) {
                result.add(apiInString);
            }
        }
        return result;
    }
}
