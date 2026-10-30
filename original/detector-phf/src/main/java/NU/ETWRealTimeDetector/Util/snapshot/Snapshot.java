package NU.ETWRealTimeDetector.Util.snapshot;

import NU.ETWRealTimeDetector.ExtraDetectionFactors.ProcessInjection;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.SensitiveProgram;
import NU.ETWRealTimeDetector.ExtraDetectionFactors.SensitiveProgram2;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.Pojo.SensitiveProgram2Info;
import NU.ETWRealTimeDetector.Pojo.etwThread;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sqlite.SQLiteConfig;

import java.io.File;
import java.io.IOException;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

public class Snapshot {
    private static Logger logger = LoggerFactory.getLogger("snapshot");
    static String dbUrl = "jdbc:sqlite:snapshot/%s.db";
    private static HashMap<String, PreparedStatement> prepMap = new HashMap<>();
    private static HashMap<String, Long> client2DeviceBootTime = new HashMap<>();

    public static Long getDeviceBootTimeFromSnapshot(String clientId) {
        if (client2DeviceBootTime.containsKey(clientId)) {
            return client2DeviceBootTime.get(clientId);
        }
        Long deviceBootTime = 0L;
        File file = new File(String.format("snapshot/%s.db", clientId));
        if (file.exists()) {
            try (Connection connection = getConnection(clientId)) {
                Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery("select deviceBootTime from ClientInfo limit 1");
                if (rs.next()) {
                    deviceBootTime = rs.getLong("deviceBootTime");
                }
                return deviceBootTime;
            } catch (SQLException e) {
                logger.warn(e.getMessage());
            }
        }
        client2DeviceBootTime.put(clientId, deviceBootTime);
        return deviceBootTime;
    }

    public static void deleteSnapshot(String clientId) {

        try {

            // 0L 代表没有快照
            client2DeviceBootTime.put(clientId, 0L);

            // 删除 sqlite db文件
            File db = new File(String.format("snapshot/%s.db", clientId));
            File dbShm = new File(String.format("snapshot/%s.db-shm", clientId));
            File dbWal = new File(String.format("snapshot/%s.db-wal", clientId));
            if (db.exists()) {
                FileUtils.forceDelete(db);
            }
            if (dbShm.exists()) {
                FileUtils.forceDelete(dbShm);
            }
            if (dbWal.exists()) {
                FileUtils.forceDelete(dbWal);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void saveUuid(int uuid) {
        try {
            FileUtils.write(new File("uuid"), String.valueOf(uuid), "utf8");
            logger.info("save uuid {}", uuid);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static int getUuid() {
        int uuid = 0;
        File file = new File("uuid");
        if (file.exists()) {
            try {
                String uuidStr = FileUtils.readFileToString(file, "utf8");
                if (uuidStr != null && uuidStr.length() > 0) {
                    uuid = Integer.valueOf(uuidStr);
                }
                //saveUuid(0);
            } catch (IOException e) {
                logger.warn(e.getMessage());
            }
        }
        logger.info("get uuid {}", uuid);
        return uuid;
    }

    public static void dumpProcessTable(String clientId, String dir, Collection<ProcessInfo> list) {
        StringBuilder builder = new StringBuilder();
        File path = ensureDumpPath(clientId, dir);
        File file = new File(path, "ProcessTable");
        list.forEach(info -> builder.append(info.toString()).append(System.lineSeparator()));
        try {
            FileUtils.write(file, builder.toString(), "utf8", true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void dumpProcessInjectionAttacker(String clientId, String dir, List<Integer> attackerUuids) {
        StringBuilder builder = new StringBuilder();
        File path = ensureDumpPath(clientId, dir);
        File file = new File(path, "ProcessInjection");
        String uuids = attackerUuids.stream().map(uuid -> uuid.toString()).collect(Collectors.joining(","));
        builder.append(uuids).append(System.lineSeparator());
        try {
            FileUtils.write(file, builder.toString(), "utf8", true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void dumpProcessInjectionvictimThread(String clientId, String dir, List<ThreadInfo> threadInfoList) {
        StringBuilder builder = new StringBuilder();
        File path = ensureDumpPath(clientId, dir);
        File file = new File(path, "ProcessInjection");
        threadInfoList.forEach(info -> builder.append(info.toString()).append(System.lineSeparator()));
        try {
            FileUtils.write(file, builder.toString(), "utf8");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static File ensureDumpPath(String clientId, String dir) {
        File path = new File(String.format("dumpSnapshot/%s/%s", clientId, dir));
        if (!path.exists()) {
            path.mkdirs();
        }
        return path;
    }

    public static void dumpSensitiveProgram2(String clientId, String dir, Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramInfos) {
        StringBuilder builder = new StringBuilder();
        File path = ensureDumpPath(clientId, dir);
        File file = new File(path, "SensitiveProgram2");
        processId2SensitiveProgramInfos.forEach((k, v) -> {
            Integer pid = k;
            v.forEach((cmd, info) -> {
                builder.append("pid:").append(pid).append(" cmd:").append(cmd).append(" ").append(info).append(System.lineSeparator());
            });
        });
        try {
            FileUtils.write(file, builder.toString(), "utf8");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void execute() {

        // 将detector检测数据持久化到sqlite
        //
        // 导出ProcessTable & ProcessNode
        // 导出ProcessInjection
        // 导出FileNode
        // 导出SensitiveProgram2


        Map<String, ProcessTable> processTableMap = ProcessTable.getAllInstance();
        //Map<String, ProcessInjection> processInjectionMap = ProcessInjection.getAllInstance();

        processTableMap.entrySet().forEach(processTableEntry -> {
            long start = System.currentTimeMillis();
            String clientId = processTableEntry.getKey();

            Connection connection = getConnection(clientId);
            initialDatabase(connection);

            ProcessTable processTable = processTableMap.get(clientId);
            DetectionFramework framework = DetectionFramework.getInstance(clientId);
            ProcessInjection processInjection = ProcessInjection.getInstance(clientId);
            SensitiveProgram2 sensitiveProgram2 = SensitiveProgram2.getInstance(clientId);
            SensitiveProgram sensitiveProgram = SensitiveProgram.getInstance(clientId);
            //FileNodeNew fileNodeNew = FileNodeNew.getInstance(clientId);

            long deviceBootTime = processTable.getDeviceBootTime();

            try {
                // save ClientInfo
                PreparedStatement prep = getPreparedStatement(connection, "InsertClientInfo");
                prep.setString(1, clientId);
                prep.setLong(2, deviceBootTime);
                int res = prep.executeUpdate();
                if (res <= 0) {
                    logger.error("insert ClientInfo failed. clientId=" + clientId + " deviceBootTime=" + deviceBootTime);
                    return;
                }
                logger.info("clientId {} 开始备份 DeviceBootTime {}", clientId, deviceBootTime);

                // save ProcessTable
                Map<Integer, Process> uuid2Process = processTable.getUuid2Process();

                int backupProcessCount = 0;
                Iterator<Process> processIterator = uuid2Process.values().iterator();
                while (processIterator.hasNext()) {
                    Process process = processIterator.next();
                    ProcessNode processNode = framework.getProcessNode(process.getUuid());
                    try {
                        prep = getPreparedStatement(connection, "InsertProcessTable");
                        prep.setLong(1, process.getUuid());
                        prep.setInt(2, process.getProcessId());
                        if (processNode == null) {
                            prep.setInt(3, 0);
                            prep.setLong(4, 0);
                        } else {
                            prep.setInt(3, processNode.getParentNode().getProcess().getProcessId());
                            prep.setLong(4, processNode.getParentNode().getUuid());
                        }
                        prep.setString(5, clientId);
                        prep.setLong(6, process.getStartTime());
                        prep.setLong(7, process.getEndTime());
                        prep.setLong(8, process.getAnyMiddleTime());
                        prep.setLong(9, process.getUpdateTime());
                        prep.setString(10, process.getFileName());
                        prep.setString(11, process.getProcessName());
                        prep.setString(12, process.getCommandLine());

                        if (processNode == null) {
                            prep.setString(13, "");
                        } else {
                            prep.setString(13, String.join(",", processNode.getLabels().stream().map(l -> l.name()).collect(Collectors.toList())));
                        }

                        res = prep.executeUpdate();
                        backupProcessCount++;
                        if (res <= 0) {
                            logger.error("insert process failed! clientId=" + clientId + " uuid=" + process.getUuid());
                        }
                    } catch (Exception e) {
                        logger.error("ProcessTable back error process:" + process + " processNode:" + processNode, e);
                    }
                }
                logger.info("ProcessTable uuid2Process {} backup process {}", uuid2Process.size(), backupProcessCount);
                logger.info("FrameWork processMap size: {}", framework.getProcessMap().size());

                // save ProcessInjection
                Set<Process> attackers = processInjection.getAttackers();
                int backAttackerCount = 0;
                Iterator<Process> attackersIterator = attackers.iterator();
                while (attackersIterator.hasNext()) {
                    Process attacker = attackersIterator.next();
                    prep = getPreparedStatement(connection, "InsertAttacker");
                    prep.setLong(1, attacker.getUuid());
                    res = prep.executeUpdate();
                    backAttackerCount++;
                    if (res <= 0) {
                        logger.error("insert attacker failed!");
                    }
                }
                logger.info("ProcessInjection attacker count: {} backup attacker count: {}",
                        attackers.size(),
                        backAttackerCount
                );

                try {
                    Map<etwThread, Process> victimThread2Attacker = processInjection.getVictimThread2Attacker();
                    int backupVictimThreadCount = 0;
                    Iterator<Map.Entry<etwThread, Process>> victimThread2AttackerIterator = victimThread2Attacker.entrySet().iterator();
                    while (victimThread2AttackerIterator.hasNext()) {
                        Map.Entry<etwThread, Process> etwThreadAttackerEntry = victimThread2AttackerIterator.next();
                        etwThread victimThread = etwThreadAttackerEntry.getKey();
                        Process attacker = etwThreadAttackerEntry.getValue();
                        prep = getPreparedStatement(connection, "InsertVictimThread");
                        prep.setInt(1, victimThread.getThreadId());
                        prep.setLong(2, victimThread.getUpdateTime());
                        prep.setInt(3, victimThread.getProcess().getUuid());
                        prep.setInt(4, attacker.getUuid());
                        res = prep.executeUpdate();
                        backupVictimThreadCount++;
                        if (res <= 0) {
                            logger.error("insert victim thread failed!");
                        }
                    }
                    logger.info("processInjection victimThreadAttacker size() {} attacker2VictimThread.size() {}  backupVictimThreadCount {}",
                            victimThread2Attacker.size(),
                            processInjection.attacker2VictimThreads.size(),
                            backupVictimThreadCount
                    );
                } catch (Exception e) {
                    logger.error("processInjection victimThreadAttacker error", e.getMessage());
                }

                // save SensitiveProgram2
                Map<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramInfos = sensitiveProgram2.getProcessId2SensitivePrograms();
                Iterator<Map.Entry<Integer, HashMap<String, SensitiveProgram2Info>>> processId2SensitiveProgramInfosIterator = processId2SensitiveProgramInfos.entrySet().iterator();
                int backupSensitiveProgram2Count = 0;
                while (processId2SensitiveProgramInfosIterator.hasNext()) {
                    Map.Entry<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramsEntry = processId2SensitiveProgramInfosIterator.next();
                    Integer processId = processId2SensitiveProgramsEntry.getKey();
                    HashMap<String, SensitiveProgram2Info> sensitiveProgram2InfoHashMap = processId2SensitiveProgramsEntry.getValue();
                    Iterator<Map.Entry<String, SensitiveProgram2Info>> sensitiveProgram2InfoIterator = sensitiveProgram2InfoHashMap.entrySet().iterator();
                    while (sensitiveProgram2InfoIterator.hasNext()) {
                        Map.Entry<String, SensitiveProgram2Info> stringSensitiveProgram2InfoEntry = sensitiveProgram2InfoIterator.next();
                        String sensitiveCmd = stringSensitiveProgram2InfoEntry.getKey();
                        SensitiveProgram2Info sensitiveProgram2Info = stringSensitiveProgram2InfoEntry.getValue();
                        prep = getPreparedStatement(connection, "InsertSensitiveProgram2");
                        prep.setInt(1, processId);
                        prep.setString(2, sensitiveCmd);
                        prep.setLong(3, sensitiveProgram2Info.getLastReportTime());
                        prep.setInt(4, sensitiveProgram2Info.getCount());
                        res = prep.executeUpdate();
                        backupSensitiveProgram2Count++;
                        if (res <= 0) {
                            logger.error("insert sensitiveProgram2 failed!");
                        }
                    }
                }
                logger.info("SensitiveProgram2 processId count: {} sensitiveProgram count: {} backupSensitiveProgram2 {}",
                        processId2SensitiveProgramInfos.size(),
                        processId2SensitiveProgramInfos.values().size(),
                        backupSensitiveProgram2Count
                );

                // save SensitiveProgram
                Map<Integer, HashSet<String>> processId2SensitivePrograms = sensitiveProgram.getProcessId2SensitivePrograms();
                Iterator<Map.Entry<Integer, HashSet<String>>> processId2SensitiveProgramsIterator = processId2SensitivePrograms.entrySet().iterator();
                int backupSensitiveProgramCount = 0;
                while (processId2SensitiveProgramsIterator.hasNext()) {
                    Map.Entry<Integer, HashSet<String>> processId2SensitiveProgramsEntry = processId2SensitiveProgramsIterator.next();
                    Integer pid = processId2SensitiveProgramsEntry.getKey();
                    HashSet<String> sensitiveCmd = processId2SensitiveProgramsEntry.getValue();
                    prep = getPreparedStatement(connection, "InsertSensitiveProgram");
                    prep.setInt(1, pid);
                    prep.setString(2, String.join(",", new ArrayList<>(sensitiveCmd)));
                    res = prep.executeUpdate();
                    backupSensitiveProgramCount++;
                    if (res <= 0) {
                        logger.error("insert sensitiveProgram failed!");
                    }
                }
                logger.info("SensitiveProgram processId count: {} sensitiveProgram count: {} backupSensitiveProgram {}",
                        processId2SensitivePrograms.size(),
                        processId2SensitivePrograms.values().size(),
                        backupSensitiveProgramCount
                );

                // save fileNodeNew 废弃
                //byte[] fileNodeFilter = fileNodeNew.getFileNodeFilterBytes();
                //byte[] fileLabelFilter = fileNodeNew.getFileLabelFilterBytes();
                //prep = getPreparedStatement(connection, "InsertFileNode");
                //prep.setString(1, clientId);
                //prep.setBytes(2, fileNodeFilter);
                //prep.setBytes(3, fileLabelFilter);
                //res = prep.executeUpdate();
                //if (res <= 0) {
                //    logger.error("add file node failed!");
                //}

                //System.out.println("fileNode backed up.");
                //logger.info("fileNodeFilter: {} fileLabelFilter: {}", fileNodeFilter.length, fileLabelFilter.length);

                connection.commit();
                prepMap.values().forEach(p -> {
                    try {
                        p.close();
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                });
                prepMap.clear();
                connection.close();
                long end = System.currentTimeMillis();
                logger.info("clientId {} 备份完成 耗时 {}ms", clientId, (end - start));
            } catch (SQLException e) {
                e.printStackTrace();
                logger.error("备份失败", e);
            }
        });
    }

    private static Connection getConnection(String clientId) {
        try {
            FileUtils.forceMkdir(new File("snapshot"));
            SQLiteConfig config = new SQLiteConfig();
            config.setJournalMode(SQLiteConfig.JournalMode.WAL);
            config.setPragma(SQLiteConfig.Pragma.SYNCHRONOUS, SQLiteConfig.SynchronousMode.OFF.name());
            config.setLockingMode(SQLiteConfig.LockingMode.EXCLUSIVE);

            String url = String.format(dbUrl, clientId);
            Connection connection = DriverManager.getConnection(url, config.toProperties());
            connection.setAutoCommit(false);
            return connection;

        } catch (SQLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void initialDatabase(Connection connection) {
        try {
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(30); // set timeout to 30 sec.

                statement.executeUpdate("drop table if exists ClientInfo");
                statement.executeUpdate("create table ClientInfo (id integer PRIMARY KEY AUTOINCREMENT,clientId string,deviceBootTime string)");
                //statement.executeUpdate("create table ClientInfo (id integer PRIMARY KEY AUTOINCREMENT,uuid integer, name string, original string)");
                //statement.executeUpdate("CREATE INDEX idx_FNode_uuid on FNode(uuid)");

                statement.executeUpdate("drop table if exists ProcessTable");
                statement.executeUpdate("create table ProcessTable (id integer PRIMARY KEY AUTOINCREMENT,uuid integer,pid integer,ppid integer,puuid integer,clientId string,startTime integer,endTime integer,anyMiddleTime integer ,updateTime integer ,fileName string,processname string,cmd string,label string);");
                //statement.executeUpdate("CREATE INDEX idx_ProcessTable_uuid on ProcessTable(uuid)");


                statement.executeUpdate("drop table if exists ProcessInjectionAttacker");
                statement.executeUpdate("create table ProcessInjectionAttacker (id integer PRIMARY KEY AUTOINCREMENT,uuid integer);");

                statement.executeUpdate("drop table if exists ProcessInjectionVicTimThread");
                statement.executeUpdate("create table ProcessInjectionVicTimThread (id integer PRIMARY KEY AUTOINCREMENT,threadId integer,updatetime integer,pUuid integer ,attackerUuid integer);");


                // SensitiveProgram2
                statement.executeUpdate("drop table if exists SensitiveProgram2");
                statement.executeUpdate("create table SensitiveProgram2 (id integer PRIMARY KEY AUTOINCREMENT,pid integer,sensitiveProgram string,lastReportTime long,count integer);");

                // SensitiveProgram
                statement.executeUpdate("drop table if exists SensitiveProgram");
                statement.executeUpdate("create table SensitiveProgram (id integer PRIMARY KEY AUTOINCREMENT,pid integer,sensitiveProgram string);");

                // todo NetworkActivity

                // FileNode blob 废弃
                //statement.executeUpdate("drop table if exists FileNode");
                //statement.executeUpdate("create table FileNode (id integer PRIMARY KEY AUTOINCREMENT,clientId String,files blob,fileLabels blob);");

                connection.commit();

            } catch (Exception e) {
                logger.error("Initial sqlite error.", e);
            }
        } catch (Exception e) {
            logger.error("initial error", e);
        }
    }

    private static PreparedStatement getPreparedStatement(Connection conn, String type) {
        PreparedStatement prep = null;
        if (prepMap.containsKey(type)) {
            return prepMap.get(type);
        }

        String sql = "";
        switch (type) {
            case "InsertClientInfo":
                sql = "insert into ClientInfo(clientId,deviceBootTime)values(?,?);";
                break;
            case "InsertProcessTable":
                sql = "insert into ProcessTable(uuid,pid,ppid,puuid,clientId,startTime,endTime,anyMiddleTime,updateTime,fileName,processName,cmd,label)values(?,?,?,?,?,?,?,?,?,?,?,?,?);";
                break;
            case "InsertAttacker":
                sql = "insert into ProcessInjectionAttacker(uuid)values(?)";
                break;
            case "InsertVictimThread":
                sql = "insert into ProcessInjectionVicTimThread(threadId,updateTime,puuid,attackerUuid)values (?,?,?,?);";
                break;
            case "InsertSensitiveProgram2":
                sql = "insert into SensitiveProgram2(pid,sensitiveProgram,lastReportTime,count)values (?,?,?,?)";
                break;
            case "InsertSensitiveProgram":
                sql = "insert into SensitiveProgram(pid,sensitiveProgram)values (?,?)";
                break;
            case "InsertFileNode":
                sql = "insert into FileNode(clientId,files,fileLabels)values (?,?,?)";
                break;
            default:
                break;
        }
        try {
            prep = conn.prepareStatement(sql);
            prep.setQueryTimeout(30);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        prepMap.put(type, prep);
        return prep;
    }

    public static String getOSSignalType() {
        return System.getProperties().getProperty("os.name").toLowerCase().startsWith("win") ? "INT" : "USR2";
    }

    public static HashMap<String, byte[]> getFileNodeByteArray(String clientId) {
        HashMap<String, byte[]> map = new HashMap<>();
        try (Connection connection = getConnection(clientId)) {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery("select * from FileNode");
            if (rs.next()) {
                byte[] files = rs.getBytes("files");
                byte[] fileLabels = rs.getBytes("fileLabels");

                map.put("files", files);
                map.put("fileLabels", fileLabels);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return map;
    }

    public static Map<Integer, HashSet<String>> getSensitiveProgram(String clientId) {
        Map<Integer, HashSet<String>> processId2SensitiveProgram = new HashMap<>();
        try (Connection conn = getConnection(clientId)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from SensitiveProgram");
            while (rs.next()) {
                int pid = rs.getInt("pid");
                String sensitiveProgram = rs.getString("sensitiveProgram");
                HashSet<String> sensitivePrograms = new HashSet<>(Arrays.asList(sensitiveProgram.split(",")));
                processId2SensitiveProgram.put(pid, sensitivePrograms);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return processId2SensitiveProgram;
    }

    public static Map<Integer, HashMap<String, SensitiveProgram2Info>> getSensitiveProgram2(String clientId) {
        HashMap<Integer, HashMap<String, SensitiveProgram2Info>> processId2SensitiveProgramInfos = new HashMap<>();

        try (Connection conn = getConnection(clientId)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from SensitiveProgram2");
            while (rs.next()) {
                Integer pid = rs.getInt("pid");
                String sensitiveProgram = rs.getString("sensitiveProgram");
                Long lastReportTime = rs.getLong("lastReportTime");
                Integer count = rs.getInt("count");

                HashMap<String, SensitiveProgram2Info> sensitiveProgram2InfoHashMap = processId2SensitiveProgramInfos.getOrDefault(pid, new HashMap<>());
                sensitiveProgram2InfoHashMap.put(sensitiveProgram, new SensitiveProgram2Info(lastReportTime, count));
                processId2SensitiveProgramInfos.putIfAbsent(pid, sensitiveProgram2InfoHashMap);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return processId2SensitiveProgramInfos;
    }

    public static HashMap<Integer, ProcessInfo> getProcessInfoList(String clientId) {
        HashMap<Integer, ProcessInfo> processInfoMap = new HashMap<>();
        try (Connection conn = getConnection(clientId)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from ProcessTable");
            while (rs.next()) {
                Long uuid = rs.getLong("uuid");
                Integer pid = rs.getInt("pid");
                Integer ppid = rs.getInt("ppid");
                Long puuid = rs.getLong("puuid");
                //String clientId = rs.getString("clientId");
                Long startTime = rs.getLong("startTime");
                Long anyMiddleTime = rs.getLong("anyMiddleTime");
                Long endTime = rs.getLong("endTime");
                Long updateTime = rs.getLong("updateTime");
                String fileName = rs.getString("fileName");
                String processName = rs.getString("processName");
                String cmd = rs.getString("cmd");
                String label = rs.getString("label");

                ProcessInfo processInfo = new ProcessInfo(uuid.intValue(), pid, ppid, puuid.intValue(), startTime, endTime, anyMiddleTime, updateTime, fileName, processName, cmd, label);
                processInfoMap.put(processInfo.getUuid(), processInfo);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return processInfoMap;
    }

    public static List<Integer> getAttackerUuids(String clientId) {
        List<Integer> attackerUuids = new ArrayList<>();
        try (Connection conn = getConnection(clientId)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from ProcessInjectionAttacker");
            while (rs.next()) {
                int uuid = rs.getInt("uuid");
                attackerUuids.add(uuid);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return attackerUuids;
    }

    public static List<ThreadInfo> getVictimThreadList(String clientId) {
        List<ThreadInfo> threadInfoList = new ArrayList<>();
        try (Connection conn = getConnection(clientId)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from ProcessInjectionVicTimThread");
            while (rs.next()) {
                int threadId = rs.getInt("threadId");
                Long updateTime = rs.getLong("updateTime");
                Integer puuid = rs.getInt("puuid");
                Integer attackerUuid = rs.getInt("attackerUuid");
                threadInfoList.add(new ThreadInfo(threadId, updateTime, puuid, attackerUuid));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return threadInfoList;
    }
}
