package NU.ETWRealTimeDetector.Cache;

import NU.ETWRealTimeDetector.Process.Process;

import java.io.Serializable;
import java.util.Objects;

public class IPInfo implements Serializable {
    private Long SourceIp;
    private Long Timestap;

    public IPInfo(Long sourceIp) {
        SourceIp = sourceIp;
    }

    public IPInfo(Long sourceIp, Long timestap) {
        SourceIp = sourceIp;
        Timestap = timestap;
    }

    public Long getSourceIp() {
        return SourceIp;
    }

    public void setSourceIp(long sourceIp) {
        this.SourceIp = sourceIp;
    }

    public void setTimestap(long timestap) {
        this.Timestap = timestap;
    }

    public Long getTimestap() {
        return Timestap;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        IPInfo ipInfo = (IPInfo) o;
        return Objects.equals(SourceIp, ipInfo.SourceIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(SourceIp);
    }

}
