package NU.ETWRealTimeDetector.Util;

import net.ipip.ipdb.CityInfo;
import org.junit.Test;

import static org.junit.Assert.*;

public class IpCityUtilTest {

    @Test
    public void getCityInfo() {
        CityInfo cityInfo = IpCityUtil.getCityInfo("127.0.0.1");
        assertNotNull(cityInfo);
        System.out.println(cityInfo.getCountryName());
        System.out.println(cityInfo.getRegionName());
        System.out.println(cityInfo.getCityName());
    }
}