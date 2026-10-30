package NU.ETWRealTimeDetector.Pojo;

import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Util.IPParser;
import NU.ETWRealTimeDetector.Util.IpCityUtil;
import com.google.common.base.Objects;
import net.ipip.ipdb.CityInfo;

import java.util.HashMap;

public class ExternalIpInfo {
    String clientId;
    Process process;
    Long timestamp;
    Long saddr;
    Integer sport;
    Long daddr;
    Integer dport;
    String protocol;

    public ExternalIpInfo(String clientId, Process process, Long timestamp, Long saddr, Integer sport, Long daddr, Integer dport, String protocol) {
        this.clientId = clientId;
        this.process = process;
        this.timestamp = timestamp;
        this.saddr = saddr;
        this.sport = sport;
        this.daddr = daddr;
        this.dport = dport;
        this.protocol = protocol;
    }

    public HashMap<String, String> toMap() {
        HashMap<String, String> map = new HashMap<>(9);
        map.put("clientID", clientId);
        map.put("pid", String.valueOf(process.getProcessId()));
        String appPath = process.hasProcessName() ? process.getProcessName() : process.getFileName();
        map.put("appPath", appPath);
        map.put("timestamp", String.valueOf(timestamp));
        map.put("saddr", IPParser.parseIpAddress(saddr));
        map.put("sport", String.valueOf(IPParser.parsePort(sport)));
        String daddrStr = IPParser.parseIpAddress(daddr);
        map.put("daddr", daddrStr);
        map.put("dport", String.valueOf(IPParser.parsePort(dport)));
        map.put("protocol", protocol);

        CityInfo cityInfo = IpCityUtil.getCityInfo(daddrStr);
        if (cityInfo != null) {
            String countryName = cityInfo.getCountryName();
            String regionName = cityInfo.getRegionName();
            String cityName = cityInfo.getCityName();
            if (countryName.equals("局域网") || countryName.equals("保留地址") || countryName.equals(regionName)) {
                regionName = "";
                cityName = "";
            }
            map.put("country", countryName);
            map.put("region", regionName);
            map.put("city", cityName);
        } else {
            map.put("country", "");
            map.put("region", "");
            map.put("city", "");
        }
        return map;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExternalIpInfo that = (ExternalIpInfo) o;
        return Objects.equal(clientId, that.clientId) &&
                Objects.equal(daddr, that.daddr) &&
                Objects.equal(process.getProcessName(), that.process.getProcessName());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(clientId, daddr, process.getProcessName());
    }
}
