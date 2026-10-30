package NU.ETWRealTimeDetector.Framework.Event;


import NU.ETWRealTimeDetector.Framework.ISignalForCS;
import NU.ETWRealTimeDetector.Process.Process;

public class EventForCS implements ISignalForCS {
    protected EventType type;
    protected String clientId = "";
    protected Process process;
    protected long timestamp = 0L;
    protected int parentUuid = -1;
    protected String string1 = "";
    protected String string2 = "";

    public EventForCS(EventType type, String clientId, Process process, long timestamp, int parentUuid, String string1, String string2) {
        this.type = type;
        this.clientId = clientId;
        this.process = process;
        this.timestamp = timestamp;
        this.parentUuid = parentUuid;
        this.string1 = string1.toLowerCase();
        this.string2 = string2.toLowerCase();
    }

    public EventForCS(EventType type, String clientId, Process process, long timestamp, String string1, String string2) {
        this.type = type;
        this.clientId = clientId;
        this.process = process;
        this.timestamp = timestamp;
        this.string1 = string1.toLowerCase();
        this.string2 = string2.toLowerCase();
    }


    public EventType getType() {
        return type;
    }

    public void setType(EventType type) {
        this.type = type;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    public Process getProcess() {
        return process;
    }

    @Override
    public long getTimestamp() {
        return timestamp;
    }

    public int getParentUuid() {
        return parentUuid;
    }

    public String getString1() {
        return string1;
    }

    public String getString2() {
        return string2;
    }

    public String getOldName() {
        return string1;
    }

    public String getNewName() {
        return string2;
    }

    @Override
    public String getFileName() {
        return string1;
    }

    @Override
    public boolean isEvent() {
        return true;
    }

}
