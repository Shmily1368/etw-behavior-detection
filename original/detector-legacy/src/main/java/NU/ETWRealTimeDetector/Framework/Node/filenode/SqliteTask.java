package NU.ETWRealTimeDetector.Framework.Node.filenode;

import java.sql.Connection;

public interface SqliteTask {
    void execute(Connection conn);
}
