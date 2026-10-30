package NU.ETWRealTimeDetector.Util;


import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class UUIDTest {
    @Test
    public void uuid() {
        //205108
        long uuid = 205108L;
        String uuidStr = UUID.nameUUIDFromBytes(String.valueOf(uuid).getBytes()).toString();
        System.out.println(uuidStr);


        String str = "[License--2.0,Variable Extension-2.0]";
        str = str.replace("[", "").replace("]", "");
        List<String> list = Arrays.stream(str.split(","))
                .map(s -> s.split("-")[0])
                .map(s -> s.replace(" ", ""))
                .collect(Collectors.toList());
        System.out.println(String.join(",", list));
    }
}
