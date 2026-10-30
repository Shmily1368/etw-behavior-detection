package NU.ETWRealTimeDetector.Pojo;

import NU.ETWRealTimeDetector.Util.IPParser;
import com.google.common.base.Objects;
import org.apache.commons.net.util.SubnetUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class IpRangeInfo {
    int begin;
    int end;

    private IpRangeInfo(int begin, int end) {
        this.begin = begin;
        this.end = end;
    }

    public static IpRangeInfo parseIpRangeInfo(String config) {
        int begin = 0, end = 0;
        if (config.contains("/")) {// CIDR模式 例如 127.0.0.1/24
            try {
                SubnetUtils.SubnetInfo subnetInfo = new SubnetUtils(config).getInfo();
                String lowAddr = subnetInfo.getLowAddress();
                String highAddr = subnetInfo.getHighAddress();

                begin = subnetInfo.asInteger(lowAddr);
                end = subnetInfo.asInteger(highAddr);
            } catch (Exception e) {
                return null;
            }
        } else if (config.contains("-")) {// IP范围 例如 127.0.0.1-127.0.0.1
            String[] arr = config.split("-");
            List<Integer> ips = Arrays.stream(arr)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .filter(IPParser::isIpReg)
                    .map(s -> IPParser.toInteger(s))
                    .sorted(Integer::compareTo)
                    .collect(Collectors.toList());

            if (ips.size() != 2) {
                return null;
            }

            begin = ips.get(0);
            end = ips.get(1);

            if (begin > end) {
                return null;
            }
        } else {// 单个IP 例如 127.0.0.1
            boolean isIP = IPParser.isIpReg(config);
            if (!isIP) {
                return null;
            }

            begin = IPParser.toInteger(config);
            end = begin;
        }

        return new IpRangeInfo(begin, end);
    }

    public boolean isInRange(int intIp) {
        return begin <= intIp && intIp <= end;
    }

    public boolean isInRange(String ip) {
        int intIp = 0;
        try {
            intIp = IPParser.toInteger(ip);
        } catch (Exception e) {
            return false;
        }
        return begin <= intIp && intIp <= end;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IpRangeInfo that = (IpRangeInfo) o;
        return begin == that.begin &&
                end == that.end;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(begin, end);
    }
}
