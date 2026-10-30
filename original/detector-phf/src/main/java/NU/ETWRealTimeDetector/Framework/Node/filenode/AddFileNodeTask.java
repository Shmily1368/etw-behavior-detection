package NU.ETWRealTimeDetector.Framework.Node.filenode;

import NU.ETWRealTimeDetector.Framework.Node.FileNodeV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;
import java.util.stream.Collectors;

public class AddFileNodeTask implements SqliteTask {
    private static final Logger logger = LoggerFactory.getLogger("sqliteTask");
    private static final String sql = "insert into filenode (clientId,name,label,pathUuid) values(?,?,?,?);";

    private FileNodeV2 fileNodeV2;

    public AddFileNodeTask(final FileNodeV2 fileNodeV2) {
        this.fileNodeV2 = fileNodeV2;
    }

    @Override
    public void execute(Connection conn) {
        try (PreparedStatement prep = conn.prepareStatement(sql)) {
            prep.setString(1, fileNodeV2.getClientId());
            prep.setString(2, fileNodeV2.getFilePath());
            prep.setString(3, fileNodeV2.getLabels().stream().map(Enum::name).collect(Collectors.joining(",")));
            prep.setLong(4, fileNodeV2.getUuid());
            int res = prep.executeUpdate();
            if (res <= 0) {
                logger.warn("add file node failed! ");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

    }

    @Override
    public String toString() {
        return "AddFileNodeTask{" + "fileNodeV2=" + fileNodeV2 + '}';
    }
}
