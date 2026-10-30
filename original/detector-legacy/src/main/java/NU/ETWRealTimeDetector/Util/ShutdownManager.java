package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.IPC.TopicController;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageReceiver;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;

public class ShutdownManager implements Runnable {
    private static boolean shuttingDown = false;

    public synchronized static void shutdown() {
        if (shuttingDown) {
            return;
        }

        shuttingDown = true;

        Thread backupThread = new Thread(() -> {
            try {
                System.out.println("receive shutdown signal");
                TopicController.shutdown();
                MessageReceiver.shutdown();
                CryptominingIocIp.shutdown();
                // todo 等MessageProcessor队列中事件消费完
                // todo 等Neo4jClient中事件消费完
                System.out.println("kafka consumer stopped");
                System.out.println("wait 3s for framework...");
                Thread.sleep(3000);
                System.out.println("start backing up data...");

                // 停止ProcessTable中的定时清理Process
                ProcessTable.shutdown();

                // 备份检测数据
                Snapshot.execute();

                // 备份uuid
                Snapshot.saveUuid(Process.counter.get());

                System.out.println("Backed up data.");
                //System.out.println("Goodbye!");
                //Runtime.getRuntime().exit(0);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
        backupThread.start();
    }

    @Override
    public void run() {
        HttpServer shutdownInstruction = new HttpServer();
        shutdownInstruction.start();
    }
}
