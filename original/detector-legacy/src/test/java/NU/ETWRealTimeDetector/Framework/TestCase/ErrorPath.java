package NU.ETWRealTimeDetector.Framework.TestCase;

import NU.ETWRealTimeDetector.EventRecord.EtwEventType;
import NU.ETWRealTimeDetector.EventRecord.EventRecord;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * 盘符错误的测试
 */
public class ErrorPath {

    @Test
    public void read() {
        Neo4jClient neo4jClient = Neo4jClient.getInstance();
        String clientId = "test";
        MessageProcessor processor = new MessageProcessor(null);
        processor.setCurrent(clientId);

        List<EventRecord> records = new ArrayList<>();

        //{"processId":74208,"threadId":-1,"eventName":"ProcessDCStart","timestamp":1564557714373310700,"callstack":"null","arguments":{"ParentId":"74208","UserSID":"S-1-5-21-725301643-2188674802-4228798930-1002&0","CommandLine":"\??\C:\WINDOWS\system32\conhost.exe 0x4","ImageFileName":"conhost.exe","ProcessId":"74984"}}
        EventRecord errorPathRecord = new EventRecord(EtwEventType.ImageDCStart, 74208, -1, 1564557714373310700L);
        errorPathRecord.argument.put("ParentId", "74208");
        errorPathRecord.argument.put("UserSID", "S-1-5-21-725301643-2188674802-4228798930-1002&0");
        errorPathRecord.argument.put("CommandLine", "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0x4");
        errorPathRecord.argument.put("ParentId", "74208");
        errorPathRecord.argument.put("ImageSize", "57344");
        errorPathRecord.argument.put("FileName", "C:\\??\\C:\\Program Files (x86)\\Common Files\\microsoft shared\\TigerKin\\xmsec64.sys");
        errorPathRecord.argument.put("ProcessId", "0");
        errorPathRecord.argument.put("ImageBase", "-877744986521");

        records.add(errorPathRecord);

        records.forEach(record -> {
            processor.distributeRecord(record);
        });


    }
}
