package NU.ETWRealTimeDetector.Process;


import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ProcessTableTest {
    private static final String clientId = "testClientId";
    private static final Integer processId_6068 = 6068;

    private List<ProcessTemp> processTempList = new ArrayList<>(Arrays.asList(
            new ProcessTemp(processId_6068, "vbc.exe", "15:15", "15:15", 1558682134538223500L, 1558682134714884600L, "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\vbc.exe", 1558682134540947700L),
            new ProcessTemp(processId_6068, "conhost.exe", "15:15", "15:15", 1558682153800176100L, 1558682154061603500L, "C:\\Windows\\System32\\conhost.exe", 1558682153807108700L),
            new ProcessTemp(processId_6068, "conhost.exe", "15:16", "15:16", 1558682193172259900L, 1558682193347831900L, "C:\\Windows\\System32\\conhost.exe", 1558682193191376700L),
            new ProcessTemp(processId_6068, "conhost.exe", "15:17", "15:17", 1558682279356414800L, 1558682279506691600L, "C:\\Windows\\System32\\conhost.exe", 1558682279358431200L),
            new ProcessTemp(processId_6068, "vbc.exe", "15:18", "15:18", 1558682298804748400L, 1558682299036338400L, "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\vbc.exe", 1558682298807673300L),
            new ProcessTemp(processId_6068, "vbc.exe", "15:18", "15:18", 1558682308924906200L, 1558682309184835900L, "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\vbc.exe", 1558682308930898700L),
            new ProcessTemp(processId_6068, "vbc.exe", "15:20", "15:20", 1558682430089791500L, 1558682430276463900L, "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\vbc.exe", 1558682430092128100L),
            new ProcessTemp(processId_6068, "conhost.exe", "15:22", "15:22", 1558682546733378600L, 1558682546979270600L, "C:\\Windows\\System32\\conhost.exe", 1558682546738653300L),

            new ProcessTemp(processId_6068, "cmd.exe", "15:23", "15:23", 1558682603820781600L, 1558682607317491500L, "C:\\Windows\\System32\\cmd.exe", 1558682603834269100L),
            new ProcessTemp(processId_6068, "bozokserver.exe", "15:23", "15:52", 1558682627323518000L, 1558684330671657700L, "C:\\Windows\\bozokserver.exe", 1558682627329140300L)

    ));


    //15:15 pid 6068 vbc.exe ProcessStart 1558682134538223500
    //ImageLoad C:\Windows\Microsoft.NET\Framework64\v2.0.50727\vbc.exe 1558682134540947700
//15:15 pid 6068 vbc.exe ProcessEnd  1558682134714884600
//
//15:15 pid 6068 conhost.exe ProcessStart 1558682153800176100
    //ImageLoad C:\Windows\System32\conhost.exe 1558682153807108700
//15:15 pid 6068 conhost.exe ProcessEnd   1558682154061603500
//
//15:16 pid 6068 conhost.exe ProessStart 1558682193172259900
    //ImageLoad C:\Windows\System32\conhost.exe 1558682193191376700
//16:16 pid 6068 conhost.exe ProcessEnd  1558682193347831900
//
//15:17 pid 6068 conhost.exe ProcessStart 1558682279356414800
    //ImageLoad C:\Windows\System32\conhost.exe  1558682279358431200
//15:17 pid 6068 conhost.exe ProcessEnd   1558682279506691600
//
//15:18 pid 6068 vbc.exe ProcessStart 1558682298804748400
    //ImageLoad C:\Windows\Microsoft.NET\Framework64\v2.0.50727\vbc.exe 1558682298807673300
//15:18 pid 6068 vbc.exe ProcessEnd   1558682299036338400
//
//15:18 pid 6068 vbc.exe ProcessStart 1558682308924906200
    //ImageLoad C:\Windows\Microsoft.NET\Framework64\v2.0.50727\vbc.exe 1558682308930898700
//15:18 pid 6068 vbc.exe ProcessEnd   1558682309184835900
//
//15:20 pid 6068 vbc.exe ProcessStart 1558682430089791500
    //ImageLoad C:\Windows\Microsoft.NET\Framework64\v2.0.50727\vbc.exe 1558682430092128100
//15:20 pid 6068 vbc.exe ProcessEnd   1558682430276463900
//
//15:22 pid 6068 conhost.exe ProcessStart 1558682546733378600
    //ImageLoad C:\Windows\System32\conhost.exe 1558682546738653300
//15:22 pid 6068 conhost.exe ProcessEnd   1558682546979270600
//
//
//15:23 pid 6068 cmd.exe ProcessStart 1558682603820781600
    //ImageLoad C:\Windows\System32\cmd.exe 1558682603834269100
//15:23 pid 6068 cmd.exe ProcessEnd   1558682607317491500
//
//15:23 pid 6068 bozokserver.exe ProcessStart 1558682627323518000
    //ImageLoad C:\Windows\bozokserver.exe 1558682627329140300
//15:26   ImageLoad Certificate 1  timestamp 15:20 1558682430092128100
//15:52 pid 6068 bozokserver.exe ProcessEnd       1558684330671657700
    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void addProcessStart() {
        ProcessTable processTable = ProcessTable.getInstance(clientId);

        for (ProcessTemp process : processTempList) {
            processTable.addProcessStart(process.pid, process.startTimeStamp, process.processName, "", false);
            processTable.addImageLoad(process.pid, process.imageLoadTimeStamp, process.imageFileName);
            processTable.addProcessEnd(process.pid, process.endTimeStamp, process.processName);
        }

        Process process = processTable.getProcessOrCreateOneIfNotExist(processId_6068, 1558682430092128100L);
        assertEquals(process.getFileName(), "vbc.exe");
        //processTable.addImageLoad(processId_6068, 1558682430092128100L, "vbc.exe");


        assertTrue(processTable.getMostRecentProcess(processId_6068).getFileName().equals("bozokserver.exe"));

    }

    @Test
    public void addImageLoad() {
    }

    @Test
    public void addProcessEnd() {
    }

    @Test
    public void getProcessOrCreateOneIfNotExist() {
    }

    @Test
    public void getCurrentAliveProcess() {
    }

    @Test
    public void getMostRecentProcess() {
    }

    @Test
    public void getProcessByUuid() {
    }

    @Test
    public void testEnsureFileName() {
        Process process = new Process("test", 1, 1, "cmd");
        process.setProcessName("c:\\abc.exe");

        assertTrue(process.getFileName().isEmpty());
        process.ensureFileName();
        assertFalse(process.getFileName().isEmpty());
    }

    class ProcessTemp {
        public ProcessTemp(int pid, String processName, String startTime, String endTime, long startTimeStamp, long endTimeStamp, String imageFileName, long imageLoadTimeStamp) {
            this.pid = pid;
            this.processName = processName;
            this.startTime = startTime;
            this.endTime = endTime;
            this.startTimeStamp = startTimeStamp;
            this.endTimeStamp = endTimeStamp;

            this.imageFileName = imageFileName;
            this.imageLoadTimeStamp = imageLoadTimeStamp;
        }

        int pid;
        String processName;
        String startTime;
        String endTime;
        long startTimeStamp;
        long endTimeStamp;

        String imageFileName;
        long imageLoadTimeStamp;
    }
}