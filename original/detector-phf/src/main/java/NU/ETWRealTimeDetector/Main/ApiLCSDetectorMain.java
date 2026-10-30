package NU.ETWRealTimeDetector.Main;

import NU.ETWRealTimeDetector.ExtraDetectionFactors.ThreatIntelligence;
import NU.ETWRealTimeDetector.Framework.Node.filenode.FileNodeManager;
import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.IPC.TopicController;
import NU.ETWRealTimeDetector.KafkaProcessor.*;
import NU.ETWRealTimeDetector.KafkaProcessor.Virus.AntivirusProcessor;
import NU.ETWRealTimeDetector.KafkaProcessor.Virus.DefenseWay;
import NU.ETWRealTimeDetector.Neo4j.GraphReceiver;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.KafkaTopic;
import NU.ETWRealTimeDetector.Util.Register;
import NU.ETWRealTimeDetector.Util.ShutdownManager;
import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;
import NU.ETWRealTimeDetector.alarm.AlarmProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;

public class ApiLCSDetectorMain {

    private static Logger logger = LoggerFactory.getLogger(ApiLCSDetectorMain.class);
    private static Logger friendlyLogger = LoggerFactory.getLogger("FriendlyLogger");
    private static LinkedBlockingQueue<String> commandQueue = new LinkedBlockingQueue<>();
    private static final LinkedBlockingQueue<DefenseWay> defenseWay = new LinkedBlockingQueue<>();

    public static void main(String[] args) throws IOException, ExecutionException, InterruptedException {

        logger.info("Detector Version 2019.01.08");
        SysConfig.load("DebugConfig.xml");
        logger.info("DebugConfig loaded");

        ThreatIntelligence.init();

        FileNodeManager.init();

        // 从快照中恢复uuid
        int uuid = Snapshot.getUuid();
        //uuid会10000写一次，为了保证uuid不重复，至少增加10001
        uuid += 10500;
        Snapshot.saveUuid(uuid);
        Process.counter.set(uuid);

        // 清空topic
        KafkaTopic kafkaTopic = new KafkaTopic(SysConfig.getString("KafkaBrokerServer", ""));
        kafkaTopic.deleteTopic(Boolean.valueOf(System.getenv("DeleteTopic")), System.getenv("TopicPrefix"));

        String brokerServer = SysConfig.getString("KafkaBrokerServer", "127.0.0.1:9092");
        String consumerGroup = SysConfig.getString("KafkaConsumerGroup", "testGroup1");
        logger.info("ConsumerGroup: {}", consumerGroup);

        //Signature signature = Signature.getSignature();
        //logger.info("signature loaded");

        Thread kafkaReceiver = new KafkaReceiver(brokerServer, consumerGroup, commandQueue);
        kafkaReceiver.start();
        logger.info("kafkaReceiver started");
        friendlyLogger.info("准备开启ReceiverManager");
        ReceiverManager receiverManager = new ReceiverManager(brokerServer, consumerGroup);
        friendlyLogger.info("ReceiverManager启动成功");
        logger.info("ReceiverManager ready");
        Runnable topicController = new TopicController(receiverManager, commandQueue);
        Thread topicControllerThread = new Thread(topicController);
        topicControllerThread.start();
        logger.info("topic controller started");

        /*GraphReceiver graphReceiver = new GraphReceiver();
        graphReceiver.start();*/

        //ScheduledExecutorService pool = Executors.newSingleThreadScheduledExecutor();
        //pool.scheduleWithFixedDelay(new FileNodePersistJob(), 1, 1, TimeUnit.MINUTES);

        // 废弃
        //Runtime.getRuntime().addShutdownHook(new Thread(new FileNodePersistJob()));
        /*new ShutdownManager().run();

        logger.info("Detector Started");

        Reporter.init();

        EventProcessor eventProcessor = new EventProcessor();
        eventProcessor.start();
        logger.info("event Processor Started");

        ClientLogProcessor clientLogProcessor = new ClientLogProcessor(defenseWay);
        clientLogProcessor.start();
        logger.info("client log Processor Started");

        AntivirusProcessor antivirusProcessor = new AntivirusProcessor(defenseWay);
        antivirusProcessor.start();
        logger.info("virus Processor started");

        CepProcessor cepProcessor = new CepProcessor();
        cepProcessor.start();
        logger.info("cep Processor Started");

        EventGroupProcessor eventGroupProcessor = new EventGroupProcessor();
        eventGroupProcessor.start();
        logger.info("eventGroup Processor Started");

        AlarmProcessor alarmProcessor = new AlarmProcessor();
        alarmProcessor.start();
        logger.info("alarm processor Started");*/

        Register register = new Register();
        register.start();
    }
}
