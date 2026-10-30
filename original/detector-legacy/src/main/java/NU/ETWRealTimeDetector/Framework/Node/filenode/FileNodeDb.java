package NU.ETWRealTimeDetector.Framework.Node.filenode;

import NU.ETWRealTimeDetector.Framework.Node.FileNodeV2;
import org.apache.commons.io.FileUtils;
import org.sqlite.SQLiteConfig;

import java.io.File;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class FileNodeDb {
    private static ThreadLocal<Connection> conn = ThreadLocal.withInitial(() -> {
        ensureDbPath();
        Connection conn = null;
        SQLiteConfig config = new SQLiteConfig();
        config.setJournalMode(SQLiteConfig.JournalMode.WAL);
        config.setSynchronous(SQLiteConfig.SynchronousMode.OFF);
        try {
            conn = DriverManager.getConnection("jdbc:sqlite:db/fileNode.db", config.toProperties());
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return conn;
    });
    static ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    static Lock r = rwl.readLock();
    static Lock w = rwl.writeLock();

    static AtomicInteger writeCount = new AtomicInteger();
    static AtomicInteger readCount = new AtomicInteger();

    private static void ensureDbPath() {
        try {
            synchronized (FileNodeDb.class) {
                File path = new File("db");
                if (!path.exists()) {
                    FileUtils.forceMkdir(path);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void init() throws SQLException {
        ensureDbPath();
        SQLiteConfig config = new SQLiteConfig();
        config.setJournalMode(SQLiteConfig.JournalMode.WAL);
        //config.setLockingMode(LockingMode.NORMAL);
        //config.setOpenMode(SQLiteOpenMode.READONLY);
        config.setSynchronous(SQLiteConfig.SynchronousMode.OFF);
        //config.setPragma(Pragma.SYNCHRONOUS, SynchronousMode.OFF.name());
        Connection conn = DriverManager.getConnection("jdbc:sqlite:db/fileNode.db", config.toProperties());
        conn.setAutoCommit(false);

        try (Statement statement = conn.createStatement()) {
            statement.setQueryTimeout(30); // set timeout to 30 sec.
            statement.executeUpdate("create table if not exists filenode (id integer PRIMARY KEY AUTOINCREMENT,clientId string,name string,label string,pathUuid integer)");
            ResultSet rs = statement.executeQuery("select * from sqlite_master where type='index'");
            List<String> indexList = new ArrayList<>();
            while (rs.next()) {
                String name = rs.getString("name");
                indexList.add(name);
            }

            if (indexList.stream().noneMatch(idx -> idx.contains("filenode"))) {
                statement.executeUpdate("create index idx_filenode_pathUuid on  filenode (pathUuid)");
            }
            conn.commit();
        } catch (SQLException e1) {
            e1.printStackTrace();
        } finally {
            conn.close();
        }
    }

    public static FileNodeV2 get(long uuid) {
        r.lock();
        try (Statement stmt = conn.get().createStatement()) {
            ResultSet rs = stmt.executeQuery("select * from filenode where pathUuid=" + uuid);
            if (rs.next()) {
                String clientId = rs.getString("clientId");
                String labels = rs.getString("label");

                return new FileNodeV2(uuid, clientId, labels);
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                conn.get().commit();
            } catch (SQLException e) {
                e.printStackTrace();
            }
            r.unlock();
        }
    }

    public static void writeBatch(List<SqliteTask> tasks) {
        w.lock();
        long st = System.currentTimeMillis();
        Connection connection = conn.get();
        try {
            for (SqliteTask task : tasks) {
                task.execute(connection);
            }
            connection.commit();
            writeCount.addAndGet(tasks.size());
            long et = System.currentTimeMillis();
            long useTime = et - st;
            System.out.println(String.format("%s totalWrite:%d batch:%d useTime:%d", Thread.currentThread().toString(), writeCount.get(), tasks.size(), useTime));
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            w.unlock();
        }
    }

}
