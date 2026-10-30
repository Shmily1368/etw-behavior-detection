package NU.ETWRealTimeDetector.Util;

import org.junit.Test;

import java.util.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class StringUtilTest {

    @Test
    public void isPathRight() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("C:\\Windows\\System32\\uDWM.dll", true);
        map.put("\\Windows\\System32\\uDWM.dll", false);
        map.put("\\??\\C:\\Program Files (x86)\\Common Files\\microsoft shared\\TigerKin\\xmsec64.sys", false);
        map.put("\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.18362.235_none_5f42305c58dc2c51\\TiWorker.exe", false);
        map.put("\\Users\\mayn\\AppData\\Local\\Fork\\gitInstance\\2.20.1\\mingw64\\libexec\\git-core\\git.exe", false);
        map.put("\\Windows\\System32\\InputMethod\\CHS\\ChsIME.exe", false);
        map.put("\\Program Files (x86)\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\OFFICE16\\SDXHelper.exe", false);

        map.entrySet().stream().forEach(entry -> {
            assertTrue(StringUtil.isPathRight(entry.getKey()) == entry.getValue());
        });
    }

    @Test
    public void splitTest() {
        StringBuilder builder = new StringBuilder();
        builder.append("127.0.0.1");
        builder.append("\r\n");
        builder.append("127.0.0.1");
        String str = builder.toString();
        System.out.println(str);
        String[] arr = str.split("\\r\\n");
        System.out.println(Arrays.asList(arr));

    }

    @Test
    public void trustTest() {

        List<String> trustList = new ArrayList<>();
        trustList.add("magicmessager.exe");
        trustList.add("magicservice.exe");

        boolean trust = trustList.stream().anyMatch(t -> "C:\\Program Files (x86)\\MagProtect\\MagicMessager.exe".toLowerCase().contains(t));
        //assertTrue(trust);
        assertTrue(true && !trust);

    }
}