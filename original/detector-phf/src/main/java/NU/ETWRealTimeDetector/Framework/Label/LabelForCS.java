package NU.ETWRealTimeDetector.Framework.Label;

import NU.ETWRealTimeDetector.Framework.ISignalForCS;
import com.google.common.base.Objects;

import java.util.HashMap;
import java.util.concurrent.atomic.AtomicLong;

public class LabelForCS implements ISignalForCS {
    private static AtomicLong counter = new AtomicLong(0L);
    private Long labelId;
    private LabelType type;
    private int uuid = -1;
    private long timestamp = -1;
    private String stringField = "";
    private String clientId = "";
    private HashMap<String, String> extend = new HashMap<>();

    private LabelForCS() {
        this.labelId = counter.incrementAndGet();
    }

    public LabelForCS(LabelType type, String clientId, int uuid, long timestamp, String stringField) {
        this();
        this.type = type;
        this.clientId = clientId;
        this.uuid = uuid;
        this.timestamp = timestamp;
        this.stringField = stringField.toLowerCase();
    }

    public LabelForCS(LabelType type, String clientId, long timestamp, String stringField) {
        this();
        this.type = type;
        this.clientId = clientId;
        this.timestamp = timestamp;
        this.stringField = stringField.toLowerCase();
    }

    public LabelForCS(LabelType type, String clientId, long timestamp, String stringField, HashMap<String, String> extend) {
        this();
        this.type = type;
        this.clientId = clientId;
        this.timestamp = timestamp;
        this.stringField = stringField.toLowerCase();
        this.extend = extend;
    }

    public Long getLabelId() {
        return labelId;
    }

    public LabelType getType() {
        return type;
    }

    public int getUuid() {
        return uuid;
    }

    @Override
    public long getTimestamp() {
        return timestamp;
    }

    public String getStringField() {
        return stringField;
    }

    @Override
    public String getFileName() {
        return stringField;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    public boolean isProcessLabel() {
        return LabelType.isProcessLabel(this.type);
    }

    public boolean isFileLabel() {
        return LabelType.isFileLabel(this.type);
    }

    @Override
    public String toString() {
        return "" + type;
    }

    @Override
    public boolean isEvent() {
        return false;
    }

    public HashMap<String, String> getExtend() {
        return extend;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LabelForCS that = (LabelForCS) o;
        return uuid == that.uuid &&
                type == that.type &&
                Objects.equal(stringField, that.stringField) &&
                Objects.equal(clientId, that.clientId) &&
                Objects.equal(extend, that.extend);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(type, uuid, stringField, clientId, extend);
    }
}
