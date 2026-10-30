package NU.ETWRealTimeDetector.Framework.Event;

import NU.ETWRealTimeDetector.Process.Process;

public class NetworkEventForCS extends EventForCS {
    private Long saddr = -1L;
    private Long daddr = -1L;
    private int sport = -1;
    private int dport = -1;

    public NetworkEventForCS(EventType type, String clientId, Process process, long timestamp, Long saddr, Long daddr, int sport, int dport) {
        super(type, clientId, process, timestamp, "", "");
        this.saddr = saddr;
        this.daddr = daddr;
        this.sport = sport;
        this.dport = dport;
    }

    public Long getSaddr() {
        return saddr;
    }

    public Long getDaddr() {
        return daddr;
    }

    public int getSport() {
        return sport;
    }

    public int getDport() {
        return dport;
    }
}
