package NU.ETWRealTimeDetector.Util;

import net.ipip.ipdb.City;
import net.ipip.ipdb.CityInfo;
import net.ipip.ipdb.IPFormatException;
import net.ipip.ipdb.InvalidDatabaseException;

import java.io.IOException;

public class IpCityUtil {

    private static City db;

    static {
        try {
            db = new City("ipip.ipdb");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static CityInfo getCityInfo(String ip) {
        if (!IPParser.isIp(ip)) {
            return null;
        }

        try {
            return db.findInfo(ip, "CN");
        } catch (IPFormatException e) {
            return null;
        } catch (InvalidDatabaseException e) {
            return null;
        }
    }
}
