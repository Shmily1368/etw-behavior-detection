package NU.ETWRealTimeDetector.Pojo;

import org.junit.Test;

import static org.junit.Assert.*;

public class IpRangeInfoTest {

    @Test
    public void parseIpRangeInfo() {
        IpRangeInfo ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1/24");
        assertNotNull(ipRangeInfo);

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1-127.0.0.1");
        assertNotNull(ipRangeInfo);

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1");
        assertNotNull(ipRangeInfo);

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1/44");
        assertNull(ipRangeInfo);

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("192.168.1.a/24");
        assertNull(ipRangeInfo);

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1-127.0.0.1");
        assertNull(ipRangeInfo);
    }

    @Test
    public void testIpRange() {

        IpRangeInfo ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1/24");
        assertNotNull(ipRangeInfo);

        assertTrue(ipRangeInfo.isInRange("127.0.0.1"));
        assertFalse(ipRangeInfo.isInRange("127.0.0.1"));

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1-127.0.0.1");
        assertTrue(ipRangeInfo.isInRange("127.0.0.1"));
        assertFalse(ipRangeInfo.isInRange("127.0.0.1"));
        assertFalse(ipRangeInfo.isInRange("127.0.0.1"));

        ipRangeInfo = IpRangeInfo.parseIpRangeInfo("127.0.0.1");
        assertFalse(ipRangeInfo.isInRange("127.0.0.1"));
        assertTrue(ipRangeInfo.isInRange("127.0.0.1"));
        assertFalse(ipRangeInfo.isInRange("127.0.0.1"));
    }
}