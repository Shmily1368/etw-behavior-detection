package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.filenode.FileNodeManager;
import com.google.common.base.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public class FileNodeV2 extends Node {
    private static final Logger logger = LoggerFactory.getLogger(FileNodeV2.class);

    public FileNodeV2(String clientId, String filePath) {
        super(clientId);
        this.filePath = filePath;
        this.uuid = UUID.nameUUIDFromBytes((clientId + filePath).getBytes()).getLeastSignificantBits();
        this.time = System.currentTimeMillis() / 1000;
    }

    public FileNodeV2(long uuid, String clientId, String labels) {
        super(clientId);
        this.uuid = uuid;
        this.clientId = clientId;
        if (labels != null && labels.length() > 0) {
            this.setLabelList(labels);
        }
    }

    private long uuid;
    private String filePath;
    private long time;

    public String getFilePath() {
        return filePath;
    }

    public long getTime() {
        return this.time;
    }

    @Override
    public long getUuid() {
        return uuid;
    }

    @Override
    public void addLabel(LabelType labelType) {
        if (existLabel(labelType)) {
            return;
        }
        super.addLabel(labelType);
        FileNodeManager.saveLabel(this);
    }

    @Override
    public String toString() {
        return "FileNodeV2{" + "uuid=" + uuid + ", filePath='" + filePath + '\'' + ", time=" + time + ", clientId='" + clientId + '\'' + ", labelList=" + getLabels() + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileNodeV2 that = (FileNodeV2) o;
        return uuid == that.uuid;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(uuid);
    }
}
