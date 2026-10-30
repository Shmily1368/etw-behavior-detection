package NU.ETWRealTimeDetector.Cache;

import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ProcessNetworkInfoTest {
    @Before
    public void before() {
        SysConfig.setInteger("KeepIpCount", 2);
    }

    @Test
    public void addIp() {
        ProcessNetworkInfo processNetworkInfo = new ProcessNetworkInfo(1);
        IPInfo ipInfoTemp = new IPInfo(1L, 1L);

        ipInfoTemp.setSourceIp(1L);
        boolean isExist = processNetworkInfo.existIp(ipInfoTemp);
        if (!isExist) {
            processNetworkInfo.addIp(1L, 1L);
        }

        ipInfoTemp.setSourceIp(2L);
        if (!isExist) {
            processNetworkInfo.addIp(2L, 2L);
        }

        ipInfoTemp.setSourceIp(3L);
        if (!isExist) {
            processNetworkInfo.addIp(3L, 3L);
        }

        ipInfoTemp.setSourceIp(1L);
        assertFalse(processNetworkInfo.existIp(ipInfoTemp));

        ipInfoTemp.setSourceIp(2L);
        assertTrue(processNetworkInfo.existIp(ipInfoTemp));

        ipInfoTemp.setSourceIp(3L);
        assertTrue(processNetworkInfo.existIp(ipInfoTemp));

    }
}