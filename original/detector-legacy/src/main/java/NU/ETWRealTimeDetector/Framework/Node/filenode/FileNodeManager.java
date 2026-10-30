package NU.ETWRealTimeDetector.Framework.Node.filenode;

import NU.ETWRealTimeDetector.Framework.Node.FileNodeV2;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

public class FileNodeManager {
    private static final Logger logger = LoggerFactory.getLogger("sqliteTask");

    // 临时文件map，当处理FileIo相关事件时将会产生FileNode对象，全部默认为临时文件，由定时任务线程将创建了5分钟以上的filenode转化为正式filenode,判断的条件是，filenode是否有标签
    private static final ConcurrentHashMap<String, FileNodeV2> tempFileMap = new ConcurrentHashMap<>();

    // 临时文件queue，将会由一个定时任务线程将临时文件 转为正式文件，目的是排除临时文件，临时文件的特点是没有任何标签
    private static final ConcurrentLinkedQueue<String> tempFileQueue = new ConcurrentLinkedQueue<>();

    // 待持久的的filenode queue,临时文件转化为正式文件后，需要进行持久化
    private static final LinkedBlockingQueue<SqliteTask> write2SqliteQueue = new LinkedBlockingQueue<>();

    // fileNode cache
    private static final com.github.benmanes.caffeine.cache.Cache<Long, FileNodeV2> fileMap =
            Caffeine.newBuilder()
                    .expireAfterWrite(1, TimeUnit.MINUTES)
                    .expireAfterAccess(1, TimeUnit.MINUTES)
                    .build();

    // 定时将临时文件转化为正式文件
    private static final ScheduledExecutorService tempFileTransPool = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "fileNodeWorker"));

    // file持久化线程
    private static final ExecutorService wirte2SqlitePool = Executors.newFixedThreadPool(1, r -> new Thread(r, "fileNodeWorker-write2sqlite"));

    private static Neo4jClient neo4jClient;

    public static void init() {
        try {
            FileNodeDb.init();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        wirte2SqlitePool.execute(new Write2SqliteJob());
        tempFileTransPool.scheduleWithFixedDelay(new TemFileTransJob(), 5, 5, TimeUnit.SECONDS);
        neo4jClient = Neo4jClient.getInstance();
    }

    public static FileNodeV2 get(final String clientId, final String path) {
        // 先从零时文件中找
        String key = String.format("%s%s", clientId, path);
        FileNodeV2 fileNode = tempFileMap.get(key);

        if (fileNode != null) {
            return fileNode;
        }

        // 如果临时文件没有，则从正式文件中找
        // 先去map中找，如果没有则去sqlite中找
        long uuid = UUID.nameUUIDFromBytes((key).getBytes()).getLeastSignificantBits();
        fileNode = fileMap.getIfPresent(uuid);
        if (fileNode != null) {
            return fileNode;
        }

        fileNode = FileNodeDb.get(uuid);
        //fileNode = Db.getV2(clientId, path);
        if (fileNode != null) {
            fileMap.put(fileNode.getUuid(), fileNode);
            return fileNode;
        }

        //fileNode = FileNodeDb.get(uuid);
        //if (fileNode != null) {
        //    fileMap.put(fileNode.getUuid(), fileNode);
        //    return fileNode;
        //}

        return null;
    }

    public static void set(final FileNodeV2 fileNodeV2) {
        String key = String.format("%s%s", fileNodeV2.getClientId(), fileNodeV2.getFilePath());
        if (tempFileMap.containsKey(key)) {
            return;
        }
        tempFileMap.put(key, fileNodeV2);
        tempFileQueue.offer(key);
    }

    public static void saveLabel(final FileNodeV2 fileNodeV2) {
        // 判断fileNode是否为临时文件，如果是临时文件直接在fileNode对象上增加label
        // 非临时文件需要持久化到sqlite

        String key = String.format("%s%s", fileNodeV2.getClientId(), fileNodeV2.getFilePath());
        if (tempFileMap.containsKey(key)) {
            return;
        } else {
            write2SqliteQueue.offer(new AddLabel(fileNodeV2.getUuid(), fileNodeV2.getLabels()));
        }
    }

    private static class Write2SqliteJob implements Runnable {
        @Override
        public void run() {
            try {
                int pollCount = 0;
                int writeCount = 0;
                List<SqliteTask> list = new ArrayList<>();
                while (true) {
                    SqliteTask task = write2SqliteQueue.poll(1, TimeUnit.SECONDS);
                    if (task == null) {
                        pollCount++;
                    } else {
                        list.add(task);
                        writeCount++;
                        pollCount = 0;
                    }

                    // 当filenode条数大于10000或者 达到指定时间 持久化filenodde
                    if (pollCount >= 3 || writeCount >= 10000) {
                        pollCount = 0;
                        if (list.isEmpty()) {
                            continue;
                        }

                        long st = System.currentTimeMillis();
                        FileNodeDb.writeBatch(list);
                        list.clear();
                        long et = System.currentTimeMillis();
                        long useTime = et - st;
                        logger.info("batchWrite:{} useTime:{} queue:{}", writeCount, useTime, write2SqliteQueue.size());
                        writeCount = 0;
                    }
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static class TemFileTransJob implements Runnable {
        @Override
        public void run() {
            if (tempFileQueue.isEmpty()) {
                return;
            }

            long st = System.currentTimeMillis();
            int tempFileCount = 0;
            int fileCount = 0;
            // 10分钟之前的时间戳
            // todo 使用配置文件
            long startTime = LocalDateTime.now().minusMinutes(1).toEpochSecond(ZoneOffset.of("+8"));

            while (true) {
                long fileNodeTime;
                String key = tempFileQueue.peek();
                if (key == null)
                    break;

                tempFileCount++;
                FileNodeV2 fileNode = tempFileMap.get(key);
                if (fileNode == null) {
                    tempFileQueue.remove(key);
                    tempFileMap.remove(key);
                    break;
                }

                fileNodeTime = fileNode.getTime();

                // fileNodeTime 大于 10分钟之前的时间戳 说明，queue头的fileNode(最老的) 的创建时间 小于10分钟，这种情况下不需要处理
                if (fileNodeTime > startTime) {
                    break;
                }

                // 判断是否为临时文件，判断条件是 fileNode是否有label
                if (!fileNode.getLabels().isEmpty()) {
                    fileMap.put(fileNode.getUuid(), fileNode);
                    write2SqliteQueue.offer(new AddFileNodeTask(fileNode));
                    fileCount++;
                } else {
                    // 临时文件 通知 illustrator 删除filenode
                    neo4jClient.removeTempFile(fileNode.getClientId(), fileNode.getUuid());
                }
                tempFileQueue.remove(key);
                tempFileMap.remove(key);
            }
            long et = System.currentTimeMillis();
            long useTime = et - st;
            logger.info("TemFileTransJob tempFileCount:{} transFileCount:{} current queue size:{}  useTime:{}", tempFileCount, fileCount, tempFileQueue.size(), useTime);
        }
    }

}
