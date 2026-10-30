package NU.ETWRealTimeDetector.Framework.Node.filenode;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Set;
import java.util.stream.Collectors;

public class AddLabel implements SqliteTask {
    private static final Logger logger = LoggerFactory.getLogger("sqliteTask");
    private static final String sql = "update filenode set label=? where pathUuid=?;";

    private long uuid;
    private String label;

    public AddLabel(long uuid, Set<LabelType> labels) {
        this.uuid = uuid;
        this.label = labels.stream().map(Enum::toString).collect(Collectors.joining(","));
    }

    @Override
    public void execute(Connection conn) {
        try (PreparedStatement prep = conn.prepareStatement(sql)) {
            prep.setString(1, label);
            prep.setLong(2, uuid);
            int res = prep.executeUpdate();
            if (res <= 0) {
                logger.warn("update file node label failed! " + this.toString());
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
        return "AddLabel{" + "uuid=" + uuid + ", label='" + label + '\'' + '}';
    }
}
