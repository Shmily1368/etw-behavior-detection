package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;


public class FileNode extends Node implements Serializable {
    private String filePath = "";
    private long uuid;
    private boolean isRightPath;

    private static AtomicLong counter = new AtomicLong(-1);
    private static Neo4jClient neo4jClient = Neo4jClient.getInstance();
    private static final Logger logger = LoggerFactory.getLogger(FileNode.class);

    public FileNode(String filePath, String clientId) {
        super(clientId);
        isRightPath = StringUtil.isPathRight(filePath);
        if (!isRightPath) {
            int indexOfColon = filePath.indexOf(':');
            if (indexOfColon > -1) {
                filePath = filePath.substring(indexOfColon);
            }
        }

        this.filePath = filePath;
        this.uuid = counter.decrementAndGet();
        //;neo4jClient.addFileNode(this);
        logger.info("fileNode:" + uuid + " " + this);
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath, boolean affectNeo4j) {
        boolean isRightPath = StringUtil.isPathRight(filePath);
        if (!isRightPath) {
            // 当盘符路径不正确时，保存去掉错误盘符的结果
            int indexOfColon = filePath.indexOf(':');
            if (indexOfColon > -1) {
                filePath = filePath.substring(indexOfColon);
            }
        }

        // 如果fileNode的路径是错误的，并且更新了正确的路径，需要同步到neo4j
        if (isRightPath && affectNeo4j) {
            neo4jClient.updateFileName(clientId, this.uuid, filePath);
        }
        this.filePath = filePath;
    }

    public boolean isPathRight() {
        return isRightPath;
    }

    @Override
    public long getUuid() {
        return uuid;
    }

    @Override
    public String toString() {
        return filePath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof FileNode))
            return false;

        FileNode fileNode = (FileNode) o;

        return uuid == fileNode.uuid;
    }

    @Override
    public int hashCode() {
        return (int) (uuid ^ (uuid >>> 32));
    }
}
