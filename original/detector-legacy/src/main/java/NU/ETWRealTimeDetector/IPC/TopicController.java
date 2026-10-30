package NU.ETWRealTimeDetector.IPC;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.KafkaProcessor.ReceiverManager;
import NU.ETWRealTimeDetector.KafkaProcessor.TopicInfo;
import NU.ETWRealTimeDetector.Pojo.IpRangeInfo;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.IPParser;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TopicController implements Runnable {
    private static final int MAX_Client_Per_Proessor = SysConfig.getInteger("MaxClientPerProessor", 50);
    private ReceiverManager receiverManager;
    private LinkedBlockingQueue<String> commandQueue;

    private final Logger topicLogger = LoggerFactory.getLogger("topic");
    private ConcurrentLinkedQueue<AlterTopicCommand> cachedCommand = new ConcurrentLinkedQueue<>();
    private TimerTask clearCache = new TimerTask() {
        @Override
        public void run() {
            while (!cachedCommand.isEmpty()) {
                Map<String, String> topicNameAndClientIdToStart = new HashMap<>();
                Set<TopicInfo> topicInfos = new HashSet<>();

                Map<String, String> topicNameAndClientIdToStop = new HashMap<>();
                for (int i = 0; i < 10; i++) {
                    AlterTopicCommand command = cachedCommand.poll();
                    if (command != null) {
                        if (command.operation == Operation.Add) {
                            topicNameAndClientIdToStart.put(command.topicName, command.clientId);
                            TopicInfo topicInfo = new TopicInfo(command.clientId, command.uuid, command.ip, command.topicName, command.offset, command.honeyPot);
                            if (topicInfos.contains(topicInfo)) {

                                topicInfo = topicInfos.stream()
                                        .filter(t -> t.getClientId().equals(command.clientId) && t.getTopicName().equals(command.topicName))
                                        .findFirst().get();

                                topicInfo.setHoneyPot(command.honeyPot);
                                topicInfo.setOffset(command.offset);
                            } else {
                                topicInfos.add(topicInfo);
                            }
                        } else if (command.operation == Operation.Remove) {
                            topicNameAndClientIdToStop.put(command.topicName, command.clientId);
                        }
                    }
                }
                // NOTE: remove has to be earlier than add
                if (topicNameAndClientIdToStop.size() != 0) {
                    // 暂时不处理shutdown，shutdown需要保存快照，下次启动分配到上次的receiver
                    //receiverManager.requestStopTopic(topicNameAndClientIdToStop);
                }
                if (topicNameAndClientIdToStart.size() != 0) {
                    receiverManager.addTopics(topicInfos);
                }
            }
        }
    };

    public TopicController(ReceiverManager receiverManager, LinkedBlockingQueue<String> commandQueue) {
        this.receiverManager = receiverManager;
        this.commandQueue = commandQueue;
        timer = new Timer();
        timer.scheduleAtFixedRate(clearCache, 10000, 10000);
    }

    public static void shutdown() {
        run = false;
        timer.cancel();
    }

    private static boolean run = true;
    private static Timer timer;

    private void createFolder(String clientID) {
        String[] folders = new String[]{"csv", "txt", "dot", "dumpProcessedEvent"};
        for (String folder : folders) {
            File file = new File(String.format("%s/%s", folder, clientID));
            if (!file.exists()) {
                file.mkdirs();
            }
        }
    }

    private final Logger logger = LoggerFactory.getLogger(TopicController.class);
    private final Logger settingLogger = LoggerFactory.getLogger("setting");

    @Override
    public void run() {
        Gson gson = new Gson();
        while (run) {
            Map<String, String> parsedMessage = null;
            String message = null;
            try {
                message = commandQueue.take();
                if ("".equals(message)) {
                    continue;
                }
                Type type = new TypeToken<Map<String, String>>() {
                }.getType();
                parsedMessage = gson.fromJson(message, type);
            } catch (Exception e) {
                logger.error("gson parse error", e);
                logger.error(message);
                System.exit(1);
            }
            String action = parsedMessage.get("action");
            if ("add".equals(action)) {
                topicLogger.info("ipc receive: {}", message);
                String topic = parsedMessage.get("topic");
                String clientID = parsedMessage.get("clientID");
                String uuid = parsedMessage.get("uuid");
                String ip = parsedMessage.getOrDefault("ip", "");
                Integer offset = -2;
                if (parsedMessage.containsKey("offset")) {
                    offset = Integer.valueOf(parsedMessage.get("offset"));
                }
                Integer honeyPot = 0;
                if (parsedMessage.containsKey("honeyPot")) {
                    honeyPot = Integer.valueOf(parsedMessage.get("honeyPot"));
                    // command 的处理会有延迟，会引起无法正确识别client身份的问题，修改为在接收到clientstart事件后，立刻修改client身份

                    if (honeyPot != 0) {
                        MessageProcessor.honyPotList.put(clientID, 1);
                        topicLogger.info("set client {} as honeypot", clientID);
                    } else {
                        if (MessageProcessor.honyPotList.containsKey(clientID)) {
                            MessageProcessor.honyPotList.remove(clientID);
                        }
                        topicLogger.info("set client {} as EDR", clientID);
                    }
                }
                createFolder(clientID);
                AlterTopicCommand command = new AlterTopicCommand(Operation.Add, clientID, uuid, ip, topic, offset, honeyPot);
                cachedCommand.add(command);
            } else if ("remove".equals(action)) {
                String topic = parsedMessage.get("topic");
                String clientID = parsedMessage.get("clientID");
                AlterTopicCommand command = new AlterTopicCommand(Operation.Remove, clientID, "", "", topic);
                cachedCommand.add(command);
            } else if ("draw".equals(action)) {
                String clientID = parsedMessage.get("clientID");
                int processId = Integer.parseInt(parsedMessage.get("pid"));
                DetectionFramework framework = DetectionFramework.getInstance(clientID);
                ProcessTable processTable = ProcessTable.getInstance(clientID);
                Process process = processTable.getMostRecentProcess(processId);
                if (process != null) {
                    /*
                    logger.info("draw client {} process {}", clientID, process);
                    String dot1 = framework.chooseProcessToDraw(process.getUuid());
                    String dot2 = framework.chooseProcessRelationToDraw(process.getUuid(), -1);
                    if ("".equals(dot1)) {
                        dot1 = "error";
                    }
                    if ("".equals(dot2)) {
                        dot2 = "error";
                    }
                    SocketCommunicator communicator = SocketCommunicator.getInstance();
                    communicator.sendMessage(String.format("{\"action\":\"draw\", \"clientID\":\"%s\", \"processID\":\"%d\", \"dot1\":\"%s\", \"dot2\":\"%s\"}", clientID, processId, dot1, dot2));
                    */
                } else {
                    logger.info("request to draw client {} processID {}, but process not found", clientID, processId);
                }
            } else if ("detectorConfig".equals(action)) {
                String portListStr = parsedMessage.get("honeypot_port");
                String[] portList = portListStr.split(",");

                MessageProcessor.portList.clear();
                Set<Integer> ports = Stream.of(portList)
                        .filter(port -> StringUtils.isNumeric(port))
                        .map(port -> Integer.valueOf(port))
                        .collect(Collectors.toSet());
                MessageProcessor.portList.addAll(ports);
                settingLogger.info("receive setting honeypot_port:{}", ports.toString());

                // 外联IP排除列表
                if (parsedMessage.containsKey("honeypot_excludeExternalIp")) {
                    String ipListStr = parsedMessage.get("honeypot_excludeExternalIp");
                    String[] ipList = ipListStr.split(",");
                    MessageProcessor.excludeExternalIpList.clear();

                    Set<IpRangeInfo> ipSet = Stream.of(ipList)
                            .map(ip -> IpRangeInfo.parseIpRangeInfo(ip))
                            .filter(ip -> ip != null)
                            .collect(Collectors.toSet());

                    MessageProcessor.excludeExternalIpList.addAll(ipSet);
                    settingLogger.info("receive setting honeypot_excludeExternalIp:{}", ipListStr);
                }

                // 内联IP排除列表
                if (parsedMessage.containsKey("honeypot_excludeInternalIp")) {
                    String ipListStr = parsedMessage.get("honeypot_excludeInternalIp");
                    String[] ipList = ipListStr.split(",");
                    MessageProcessor.excludeInternalIpList.clear();

                    Set<IpRangeInfo> ipSet = Stream.of(ipList)
                            .map(ip -> IpRangeInfo.parseIpRangeInfo(ip))
                            .filter(ip -> ip != null)
                            .collect(Collectors.toSet());

                    MessageProcessor.excludeInternalIpList.addAll(ipSet);
                    settingLogger.info("receive setting honeypot_excludeInternalIp:{}", ipListStr);
                }

                // 外连ip 只上报内网ip
                if (parsedMessage.containsKey("intranet_mode")) {
                    String intranet_mode = parsedMessage.get("intranet_mode");
                    MessageProcessor.intranet_mode = intranet_mode.equals("1");
                    settingLogger.info("receive setting intranet_mode:{}", intranet_mode);
                }

                if (parsedMessage.containsKey("outer_trusty_list")) {
                    String appStrs = parsedMessage.get("outer_trusty_list");
                    Set<Integer> sets = Arrays.stream(appStrs.split("\\|"))
                            .map(s -> s.trim().toLowerCase())
                            .filter(s -> !s.isEmpty())
                            .map(s -> s.hashCode())
                            .collect(Collectors.toSet());
                    MessageProcessor.whiteAppList.clear();
                    MessageProcessor.whiteAppList.addAll(sets);
                    settingLogger.info("receive setting whiteAppList:{}", appStrs);
                }
            }
        }
    }

    class AlterTopicCommand {
        Operation operation;
        String clientId;
        String uuid;
        String ip;
        String topicName;
        Integer offset;
        Integer honeyPot;

        AlterTopicCommand(Operation operation, String clientId, String uuid, String ip, String topicName, Integer offset, Integer honeyPot) {
            this(operation, clientId, uuid, ip, topicName);
            this.offset = offset;
            this.honeyPot = honeyPot;
        }

        AlterTopicCommand(Operation operation, String clientId, String uuid, String ip, String topicName) {
            this.operation = operation;
            this.clientId = clientId;
            this.uuid = uuid;
            this.ip = ip;
            this.topicName = topicName;
        }
    }

    enum Operation {
        Add, Remove
    }
}
