package NU.ETWRealTimeDetector.KafkaProcessor;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.NetworkActivity;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.UnitTestHelper;
import org.junit.Before;
import org.junit.Test;

import java.util.StringTokenizer;

import static org.junit.Assert.assertTrue;

public class MessageProcessorTest {

    @Before
    public void setConfig() {
        SysConfig.setInteger("ProcessRetentionTime", 1);
        SysConfig.setString("Neo4jCleanPolicy", "EveryMinute");
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setInteger("ModuleSwitch", 10);
        SysConfig.setString("IllustratorTopic", "illustrator_local_1229");
        MessageProcessor.portList.add(445);
        MessageProcessor.portList.add(54409);
        CompilationConfig.DEBUG = true;
    }

    @Test
    public void process_collector_restart_should_not_create_new_process() {
        String clientId = "junitPC";
        MessageProcessor processor = new MessageProcessor(null);
        processor.setCurrent(clientId);

        // 模拟两次InitSignal ProcessNode关联

        StringBuilder builder = new StringBuilder();

        // 第一次collector 启动
        builder.append("{\"processId\":0,\"threadId\":0,\"eventName\":\"InitSignal\",\"timestamp\":0,\"callstack\":\"null\",\"arguments\":{\"DeviceBootTime\":\"1577881788\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":380,\"threadId\":5304,\"eventName\":\"ProcessDCStart\",\"timestamp\":1578367991962340500,\"callstack\":\"null\",\"arguments\":{\"ParentId\":\"380\",\"UserSID\":\"SYSTEM&0\",\"CommandLine\":\"%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16\",\"ImageFileName\":\"csrss.exe\",\"ProcessId\":\"400\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":400,\"threadId\":456,\"eventName\":\"ThreadDCStart\",\"timestamp\":1578367991962341300,\"callstack\":\"null\",\"arguments\":{\"ProcessId\":\"400\",\"TThreadId\":\"456\"}}");
        builder.append(System.lineSeparator());

        // 第二次collector 启动
        builder.append("{\"processId\":0,\"threadId\":0,\"eventName\":\"InitSignal\",\"timestamp\":0,\"callstack\":\"null\",\"arguments\":{\"DeviceBootTime\":\"1577881789\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":380,\"threadId\":3484,\"eventName\":\"ProcessDCStart\",\"timestamp\":1578368051393461700,\"callstack\":\"null\",\"arguments\":{\"ParentId\":\"380\",\"UserSID\":\"SYSTEM&0\",\"CommandLine\":\"%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16\",\"ImageFileName\":\"csrss.exe\",\"ProcessId\":\"400\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":400,\"threadId\":456,\"eventName\":\"ThreadDCStart\",\"timestamp\":1578368051393462800,\"callstack\":\"null\",\"arguments\":{\"ProcessId\":\"400\",\"TThreadId\":\"456\"}}");
        builder.append(System.lineSeparator());

        // 第一次client重启
        builder.append("{\"processId\":0,\"threadId\":0,\"eventName\":\"InitSignal\",\"timestamp\":0,\"callstack\":\"null\",\"arguments\":{\"DeviceBootTime\":\"1577881800\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":380,\"threadId\":3484,\"eventName\":\"ProcessDCStart\",\"timestamp\":1578368051393461700,\"callstack\":\"null\",\"arguments\":{\"ParentId\":\"380\",\"UserSID\":\"SYSTEM&0\",\"CommandLine\":\"%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16\",\"ImageFileName\":\"csrss.exe\",\"ProcessId\":\"400\"}}");
        builder.append(System.lineSeparator());

        builder.append("{\"processId\":400,\"threadId\":456,\"eventName\":\"ThreadDCStart\",\"timestamp\":1578368051393462800,\"callstack\":\"null\",\"arguments\":{\"ProcessId\":\"400\",\"TThreadId\":\"456\"}}");
        builder.append(System.lineSeparator());

        StringTokenizer st = new StringTokenizer(builder.toString(), System.lineSeparator());
        while (st.hasMoreElements()) {
            String line = st.nextToken();
            EventRecord eventRecord = UnitTestHelper.string2EventRecord(line);

            if (processor.exist(eventRecord)) {
                continue;
            }

            processor.distributeRecord(eventRecord);
        }

        long count = ProcessTable.getInstance(clientId).getUuid2Process().values().stream().filter(process -> process.getProcessId() == 400).count();
        assertTrue(count == 1);
    }

    @Test
    public void honeyPot_Network() {
        NetworkActivity networkActivity = NetworkActivity.getInstance("test");
        //networkActivity.reportNetwork(1, 1L, 134916288L, 35284, 4025815566L, 47873, "tcp");
    }

    @Test
    public void honeyPot_UserLogon() {

    }

    @Test
    public void testPowershellSignature() {
        String signature = "[Enumeration-0.5,Function Body--2.0,Obfuscation:Char Frequency Obfuscation,Registry-0.5,Script Execution-1.5,Script Logging--1.0,Variable Extension-2.0]";
        String label = MessageProcessor.getPowershellLabel(signature);
        System.out.println(label);
    }
}