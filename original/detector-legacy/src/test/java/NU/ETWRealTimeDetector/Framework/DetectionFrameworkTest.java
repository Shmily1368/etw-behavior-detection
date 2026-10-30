package NU.ETWRealTimeDetector.Framework;

import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;

public class DetectionFrameworkTest {

    /*
    String clientId = "WeihaoFakePC";
    DetectionFramework framework = DetectionFramework.getInstance();
    ProcessTable processTable = ProcessTable.getInstance(clientId);

    Process rootProcess;
    Process chromeProcess;
    Process calcProcess;


    @Before
    public void setup() {
        setupProcessTable();
    }

    private void setupProcessTable() {
        processTable.addProcessStart(0, 0L, "System");
        processTable.addImageLoad(0, 1L, "System");

        processTable.addProcessStart(123, 2L, "chrome.exe");
        processTable.addImageLoad(123, 3L, "C:\\chrome.exe");

        processTable.addProcessStart(234, 4L, "calc.exe");
        processTable.addImageLoad(234, 5L, "C:\\calc.exe");

        rootProcess = processTable.getProcessOrCreateOneIfNotExist(0, 2L);
        chromeProcess = processTable.getProcessOrCreateOneIfNotExist(123, 3L);
        calcProcess = processTable.getProcessOrCreateOneIfNotExist(234, 4L);
    }

    @Test
    public void test1() {
        framework.addEvent(new EventForCS(EventType.PROCESS_START, clientId, rootProcess, 0L, rootProcess.getUuid(), "", ""));
        framework.addEvent(new EventForCS(EventType.PROCESS_START, clientId, chromeProcess, 2L, rootProcess.getUuid(), "", ""));

        framework.addLabel(new LabelForCS(LabelType.PT1, clientId, chromeProcess.getUuid(), 3L, ""));
        framework.addEvent(new EventForCS(EventType.FILE_WRITE, clientId, chromeProcess, 3L, "C:\\calc.exe", ""));

        framework.addEvent(new EventForCS(EventType.PROCESS_START, clientId, calcProcess, 4L, chromeProcess.getUuid(), "", ""));
        framework.addLabel(new LabelForCS(LabelType.PT1, clientId, calcProcess.getUuid(), 5L, ""));
        framework.addLabel(new LabelForCS(LabelType.PT18, clientId, calcProcess.getUuid(), 5L, "C:\\calc.exe"));
        framework.addEvent(new EventForCS(EventType.IMAGE_LOAD, clientId, calcProcess, 5L, "C:\\calc.exe", ""));
        framework.addEvent(new EventForCS(EventType.LOAD_OWN_EXE, clientId, calcProcess, 5L, "C:\\calc.exe", ""));

        framework.addLabel(new LabelForCS(LabelType.PT5, clientId, calcProcess.getUuid(), 6L, ""));


        File relationGraph = new File("graph/" + clientId + "/pid_234_C:\\calc.exe_uuid_3_Relation.json");
        assert relationGraph.exists();
        File attackGraph = new File("graph/" + clientId + "/pid_234_C:\\calc.exe_uuid_3.json");
        assert attackGraph.exists();

    }

    @After
    public void tearDown() {
        deleteGrammar();
    }

    private void deleteGrammar() {
        File file = new File("test/trans.txt");
        file.delete();
        file = new File("test/label.txt");
        file.delete();
        file = new File("test/judge.txt");
        file.delete();
        file = new File("test/event.txt");
        file.delete();
        file = new File("test/");
        file.delete();
    }
    */
}
