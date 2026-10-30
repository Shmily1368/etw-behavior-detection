package NU.ETWRealTimeDetector.Util;

import org.junit.Test;

import static org.junit.Assert.*;

public class IPParserTest {

    @Test
    public void parseIpAddress() {
        // 2217519296 127.0.0.1
        // 187786676 180.101.49.11
        // 19704000 127.0.0.1
        String ip = "2284628160";
        String ipStr = IPParser.parseIpAddress(Long.valueOf(ip));
        //assertTrue(ipStr.equals("127.0.0.1"));


        //ipStr = IPParser.longToIp(Long.valueOf(ip));
        //System.out.println(ipStr);
        //assertTrue(ipStr.equals("127.0.0.1"));

        ip = "923445440";
        ip = "2298587328";
        ipStr = IPParser.parseIpAddress(Long.valueOf(ip));
        System.out.println(ipStr);
        assertTrue(ipStr.equals("127.0.0.1"));
    }

    //https://www.cha127.com/long2ip/
    @Test
    public void ipToLong() {
        String ip = "239.255.255.250";
        //ip = "128.1.168.192";

        Long ipLong = IPParser.ipToLong(ip);
        System.out.println(ipLong);
        //assertTrue(ipLong == 16777343L);
    }

    @Test
    public void portToInt() {
        int port = IPParser.parsePort(48385);
        System.out.println(port);
    }

    @Test
    public void isIpReg() {
        String ip = "192.167.1.1";
        assertTrue(IPParser.isIpReg(ip));
        ip = "fdas";
        assertFalse(IPParser.isIpReg(ip));
        ip = "127.0.0.1";
        assertFalse(IPParser.isIpReg(ip));
        ip = "";
        assertFalse(IPParser.isIpReg(ip));
        ip = null;
        assertFalse(IPParser.isIpReg(ip));

    }

    @Test
    public void isPublicIpTest() {
        // 856336576 true

        Long ip = new Long(856336576L);
        assertTrue(IPParser.isPublicIp(ip));

        // false
        ip = new Long(2160437184L);
        assertFalse(IPParser.isPublicIp(ip));
    }

    @Test
    public void testIpRange() {
        String ip1 = "127.0.0.1";
        String ip2 = "127.0.0.1";
        String ip3 = "127.0.0.1";
        String ip4 = "127.0.0.1";
        String ip5 = "127.0.0.1";
        long ipLong1 = IPParser.ipToLong(ip1);
        long ipLong2 = IPParser.ipToLong(ip2);
        long ipLong3 = IPParser.ipToLong(ip3);
        long ipLong4 = IPParser.ipToLong(ip4);
        long ipLong5 = IPParser.ipToLong(ip5);
        System.out.println(ipLong1);
        System.out.println(ipLong2);
        System.out.println(ipLong3);
        System.out.println(ipLong4);
        System.out.println(ipLong5);

        System.out.println(IPParser.parseIpAddress(856336576L));
    }

    @Test
    public void isBroadcastAddress() {
        String ip = "127.0.0.1";
        boolean res = IPParser.isBroadcastAddress(ip);
        assertTrue(res);

        ip = "127.0.0.1";
        assertFalse(IPParser.isBroadcastAddress(ip));
    }
}