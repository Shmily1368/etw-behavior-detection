package magicshield;

import java.io.Serializable;

/**
 * DataBlock
 */
public class DataBlock implements Serializable {

    public DataBlock() {

    }

    public DataBlock(DataBlock dataBlock) {
        this.sendTime = dataBlock.sendTime;
        this.eventCount = dataBlock.eventCount;
        this.dataSize = dataBlock.dataSize;
        this.data = dataBlock.data;
    }

    @Override
    public String toString() {
        return "{" + " sendTime='" + sendTime + "'" + ", eventCount='" + eventCount + "'" + ", dataSize='" + dataSize
                + "'" + ", data='" + data.length + "'" + "}";
    }

    private static final long serialVersionUID = 1416397512171552673L;
    public long sendTime;
    public int eventCount;
    public int dataSize;
    public byte[] data;
}