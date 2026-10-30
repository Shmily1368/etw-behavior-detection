package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import org.junit.Test;

import static org.junit.Assert.*;

public class HoneyPotTest {

    @Test
    public void reportUserLogonSuccess() {
        HoneyPot honeyPot = HoneyPot.getInstance("test");
        String json = "{\"EventID\":4624,\"ProcessId\":552,\"ThreadId\":656,\"SystemTime\":\"2020-04-13T01:29:15.632093000Z\",\"SubjectUserName\":\"WSF-POC-CLIENT$\",\"SubjectDomainName\":\"WORKGROUP\",\"TargetUserName\":\"SYSTEM\",\"TargetDomainName\":\"NT AUTHORITY\",\"LogonType\":2,\"WorkstationName\":\"\",\"IpAddress\":\"-\",\"IpPort\":\"-\"}";
        Long timestamp = 1L;
        honeyPot.reportUserLogonSuccess(json, timestamp);
    }
}