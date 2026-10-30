package NU.ETWRealTimeDetector.Pojo;

import com.google.common.base.Objects;

import java.util.HashMap;

public class ThreatInfo {
    public String clientId;
    public String ip;
    public String processName;
    public String processPath;
    public String pid;
    public String timeStamp;

    public ThreatInfo(String clientId, String ip, String processName, String processPath, String pid, String timeStamp) {
        this.clientId = clientId;
        this.ip = ip;
        this.processName = processName;
        this.processPath = processPath;
        this.pid = pid;
        this.timeStamp = timeStamp;
    }

    public HashMap<String, String> toMap() {
        HashMap<String, String> map = new HashMap<>(9);

        map.put("pid", pid);
        map.put("client_id", clientId);
        map.put("process_name", processName);
        map.put("process_path", processPath);
        map.put("ip", ip);
        map.put("time_stamp", timeStamp);

        return map;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThreatInfo that = (ThreatInfo) o;
        return Objects.equal(clientId, that.clientId) &&
                Objects.equal(ip, that.ip) &&
                Objects.equal(processName, that.processName) &&
                Objects.equal(processPath, that.processPath) &&
                Objects.equal(pid, that.pid) &&
                Objects.equal(timeStamp, that.timeStamp);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(clientId, ip, processName, processPath, pid, timeStamp);
    }
}
