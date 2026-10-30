package NU.ETWRealTimeDetector.Util.snapshot;

import NU.ETWRealTimeDetector.Pojo.SensitiveProgram2Info;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class SnapshotTest {

    @Test
    public void saveUuid() throws IOException {
        int uuid = 1;
        Snapshot.saveUuid(uuid);
        File file = new File("uuid");
        String uuid_ss = FileUtils.readFileToString(file, Charset.forName("utf8"));
        assertEquals(String.valueOf(uuid), uuid_ss);
    }

    @Test
    public void dumpProcessTable() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("YYYY-MM-dd-HH-mm-ss");
        String timeNow = now.format(dtf);
        Collection<ProcessInfo> list = new ArrayList<>();
        list.add(new ProcessInfo(1, 1, 1, 1, 1L, 1L, 1L, 1L, "1", "1", "cmd", "PT1"));
        list.add(new ProcessInfo(1, 1, 1, 1, 1L, 1L, 1L, 1L, "1", "1", "cmd", "PT1"));
        list.add(new ProcessInfo(1, 1, 1, 1, 1L, 1L, 1L, 1L, "1", "1", "cmd", "PT1"));
        list.add(new ProcessInfo(1, 1, 1, 1, 1L, 1L, 1L, 1L, "1", "1", "cmd", "PT1"));
        Snapshot.dumpProcessTable("1", timeNow, list);
    }

    @Test
    public void dumpSensitiveProgram2() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("YYYY-MM-dd-HH-mm-ss");
        String timeNow = now.format(dtf);
        Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramInfos = new HashMap<>();
        HashMap<String, SensitiveProgram2Info> infos = new HashMap<>();
        infos.put("cmd", new SensitiveProgram2Info(432432432432432L, 200));
        processId2SensitiveProgramInfos.put(1, infos);

        Snapshot.dumpSensitiveProgram2("1", timeNow, processId2SensitiveProgramInfos);
    }
}