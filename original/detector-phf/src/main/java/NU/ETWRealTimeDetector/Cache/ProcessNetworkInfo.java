package NU.ETWRealTimeDetector.Cache;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.IPParser;
import com.google.gson.Gson;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

public class ProcessNetworkInfo implements Serializable {
    private static final int ipCount = SysConfig.getInteger("KeepIpCount", 100);
    private Integer processUuid;
    private Queue<IPInfo> ipInfos;

    public ProcessNetworkInfo(Integer processUuid) {
        this.processUuid = processUuid;
        ipInfos = new LinkedList<>();
    }

    public void addIp(Long ip, Long timestamp) {
        IPInfo ipInfo;
        if (ipInfos.size() >= ipCount) {
            ipInfo = ipInfos.poll();
            ipInfo.setSourceIp(ip);
            ipInfo.setTimestap(timestamp);
        } else {
            ipInfo = new IPInfo(ip, timestamp);
        }
        ipInfos.offer(ipInfo);
    }

    public boolean existIp(IPInfo ipInfo) {

        return ipInfos.contains(ipInfo);
    }

    public boolean isEmpty() {
        return ipInfos.isEmpty();
    }

    public List<IPInfo> getIpInfos() {
        return ipInfos.stream().collect(Collectors.toList());
    }

    public String toJson() {
        Gson gson = new Gson();
        List<HashMap> maps = ipInfos.stream().map(ip -> {
            HashMap<String, String> map = new HashMap<>(2);
            map.put("IP", IPParser.parseIpAddress(ip.getSourceIp()));
            map.put("TimeStamp", ip.getTimestap().toString());
            return map;
        }).collect(Collectors.toList());

        return gson.toJson(maps);
    }
}
