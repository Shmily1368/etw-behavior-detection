package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Event.EventForCS;
import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.Pojo.etwThread;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import com.google.common.base.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class ProcessInjection {
    private static final Logger logger = LoggerFactory.getLogger(ProcessInjection.class);
    private static Map<String, ProcessInjection> clientId2Instance = new HashMap<>();

    public static ProcessInjection getInstance(String clientId) {
        ProcessInjection instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new ProcessInjection(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    public static Map<String, ProcessInjection> getAllInstance() {
        return clientId2Instance;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private String clientId;

    // Attacter (执行注入的进程) VictimThreads 被注入时创建的线程 例如 : A -》 B A注入B进程 ,该map 会   保存 A Pid 和 在B  进程下的 线程的 对应关系
    public Map<Process, SortedSet<etwThread>> possibleAttacker2VictimThreads = new HashMap<>();
    // VictimThread 被注入时创建的进程 Attacker 注入的进程
    private Map<etwThread, Process> possibleVictimThread2Attacker = new HashMap<>();

    private Set<Process> attackers = new HashSet<>();
    private Set<Process> processAccess = new HashSet<>();
    public Map<Process, Set<etwThread>> attacker2VictimThreads = new HashMap<>();
    private Map<etwThread, Process> victimThread2Attacker = new HashMap<>();

    // NOTE: temp usage
    private Map<Process, Set<Process>> victimProcess2Attackers = new HashMap<>();

    private Queue<Process> possibleAttackerDying = new LinkedList<>();
    private Queue<Process> attackerDying = new LinkedList<>();
    private Queue<Process> vimtimDying = new LinkedList<>();

    private ConcurrentHashMap<etwThreadWrapper, CopyOnWriteArraySet<LabelForCS>> possibleVictimThread2Phf = new ConcurrentHashMap<>();
    private static ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();

    static {
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            try {

                long now = System.currentTimeMillis() / 1000;
                long limit = now - 30;

                Map<String, ProcessInjection> clientId2InstanceTemp = new HashMap<>(clientId2Instance);

                clientId2InstanceTemp.forEach((c, p) -> {

                    ConcurrentHashMap<etwThreadWrapper, CopyOnWriteArraySet<LabelForCS>> possibleVictimThread2PhfTemp = new ConcurrentHashMap<>(p.possibleVictimThread2Phf);

                    possibleVictimThread2PhfTemp.forEach((wraper, labels) -> {
                        etwThread etwThread = wraper.etwThread;
                        // 判断暂存的phf是否超时
                        if (wraper.time < limit) {
                            labels.forEach(phf -> {
                                LabelType labelType;
                                switch (phf.getType()) {
                                    case PT65:
                                        labelType = LabelType.PT5;
                                        break;
                                    case PT67:
                                        labelType = LabelType.PT7;
                                        break;
                                    case PT68:
                                        labelType = LabelType.PT8;
                                        break;
                                    case PT69:
                                        labelType = LabelType.PT9;
                                        break;
                                    case PT76:
                                        labelType = LabelType.PT16;
                                        break;
                                    default:
                                        labelType = phf.getType();
                                        break;
                                }
                                LabelForCS label = new LabelForCS(labelType, phf.getClientId(), phf.getUuid(), phf.getTimestamp(), "");
                                try {
                                    p.framework.addLabel(label);
                                } catch (IllegalStateException e) {
                                    // 这个异常可以忽略,在这段时间内collector重启，重置了ehcache缓存
                                }
                                Process attacker = p.possibleVictimThread2Attacker.get(etwThread);
                                logger.info(" thread: {} attacker: {} {} -> {}", etwThread, attacker, phf.getType(), labelType);
                            });

                            p.possibleVictimThread2Phf.remove(wraper);
                        }
                    });
                });
            } catch (Exception e) {
                //logger.error("ProcessInjection Scheduler", e);
            }

        }, 10, 10, TimeUnit.SECONDS);
    }

    private ProcessInjection(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    public Set<Process> getAttackers() {
        return attackers;
    }


    public Map<etwThread, Process> getVictimThread2Attacker() {
        return victimThread2Attacker;
    }

    public void addThreadStart(int parentProcessId, int parentThreadId, int childProcessId, int childThreadId, long timestamp) {
        // pid 4 为系统进程，会在其他进程下创建大量的线程，该进程不做处理
        if (parentProcessId == 4) {
            return;
        }

        Process parentProcess = processTable.getProcessOrCreateOneIfNotExist(parentProcessId, timestamp);
        Process childProcess = processTable.getProcessOrCreateOneIfNotExist(childProcessId, timestamp);
        etwThread parentThread = new etwThread(parentProcess, parentThreadId, timestamp);
        etwThread childThread = new etwThread(childProcess, childThreadId, timestamp);

        // 创建线程的进程跟被创建了线程的进程不是同一个，说明是注入
        if (!parentProcess.equals(childProcess)) {
            SortedSet<etwThread> possibleVictims = possibleAttacker2VictimThreads.getOrDefault(parentProcess, new TreeSet<>());
            possibleVictims.add(childThread);
            possibleAttacker2VictimThreads.putIfAbsent(parentProcess, possibleVictims);
            possibleVictimThread2Attacker.putIfAbsent(childThread, parentProcess);
            checkIfMatch(parentProcess, timestamp);
            // keep the list size being small
            removeThreadSetIfLarge3(possibleVictims);
        }


        // if the injected thread creates a new thread, it should also be regarded as an injected thread
        if (parentProcessId == childProcessId) {
            if (victimThread2Attacker.containsKey(parentThread)) {
                Process attackerProcess = victimThread2Attacker.get(parentThread);
                victimThread2Attacker.put(childThread, attackerProcess);
                attacker2VictimThreads.get(attackerProcess).add(childThread);

                //victimProcess2Attackers.put(childProcess, attackerProcess);
                Set<Process> attackers = victimProcess2Attackers.getOrDefault(childProcess, new TreeSet<>());
                victimProcess2Attackers.putIfAbsent(childProcess, attackers);
                attackers.add(attackerProcess);

                logger.info("victimProcess2Attacker {}, {}", childProcess, attackerProcess);
            } else if (possibleVictimThread2Attacker.containsKey(parentThread)) {
                Process possibleAttackerProcess = possibleVictimThread2Attacker.get(parentThread);
                possibleVictimThread2Attacker.put(childThread, possibleAttackerProcess);

                SortedSet<etwThread> possibleVictims = possibleAttacker2VictimThreads.getOrDefault(possibleAttackerProcess, new TreeSet<>());
                possibleVictims.add(childThread);
                removeThreadSetIfLarge3(possibleVictims);

                // if parent thread be removed,add to set
                if (!possibleVictimThread2Attacker.containsKey(parentThread)) {
                    possibleVictimThread2Attacker.put(parentThread, possibleAttackerProcess);
                    parentThread.setUpdateTime(timestamp + 1);
                    possibleVictims.add(parentThread);
                }
            }
        }
    }

    private void removeThreadSetIfLarge3(SortedSet<etwThread> threadSet) {
        // keep the list size being small
        int needRemoveLength = threadSet.size() - 20;
        if (needRemoveLength < 1) {
            return;
        }
        for (int i = 0; i < needRemoveLength; i++) {
            etwThread needRemoveThread = threadSet.first();
            threadSet.remove(needRemoveThread);
            possibleVictimThread2Attacker.remove(needRemoveThread);
        }
    }

    public void addPossibleInjection(Process process, long timestamp) {
        attackers.add(process);
        checkIfMatch(process, timestamp);
    }

    public void addProcessAccess(Process process, long timestamp) {
        processAccess.add(process);
        checkIfMatch(process, timestamp);
    }

    public void markInjecter(Process process, long timestamp) {
        LabelForCS label = new LabelForCS(LabelType.PT40, clientId, process.getUuid(), timestamp, "");
        framework.addLabel(label);
    }

    /**
     * 给被注入的进程产生一个Injection2事件,在该事件中会
     */
    public void markVictimProcessBeInjected(Process process, long timestamp) {

        // 获取被注入的进程

        boolean exist = victimProcess2Attackers.values().stream().flatMap(Collection::stream).anyMatch(p -> p.equals(process));
        if (!exist) {
            return;
        }

        List<Process> victimProcessList = victimProcess2Attackers.entrySet()
                .stream()
                .filter(entry -> entry.getValue().contains(process))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());


        if (victimProcessList.isEmpty()) {
            return;
        }

        victimProcessList.forEach(victimProcess -> {
            EventForCS eventForCS = new EventForCS(EventType.INJECTION2, clientId, victimProcess, timestamp, process.getUuid(), "", "");
            framework.addEvent(eventForCS);
        });

    }

    private void checkIfMatch(Process process, long timestamp) {
        boolean contains = attackers.contains(process) && possibleAttacker2VictimThreads.containsKey(process);

        if (contains) {
            Set<etwThread> victimThreads = attacker2VictimThreads.getOrDefault(process, new HashSet<>());
            // http://193.112.197.128/T2626
            // 修改该task问题
            // 先排除Pid 4
            // 有同名取同名 被注入进程中如果有 跟注入进程同名的进程，将其余进程排除
            // 其余情况 画图中会把第一个画出来

            Set<etwThread> possibleVictimThreads = possibleAttacker2VictimThreads.get(process);

            // 排除pid 4
            possibleVictimThreads = possibleVictimThreads.stream()
                    .filter(etwThread -> etwThread.getProcess().getProcessId() != 4)
                    .collect(Collectors.toSet());

            // 根据被注入的线程，找到被注入的进程
            Set<Process> victimProcesses = possibleVictimThreads
                    .stream()
                    .map(etwThread -> etwThread.getProcess())
                    .collect(Collectors.toSet());

            // 从被注入的进程中 找出跟注入进程同名的进程
            Set<Process> realVictimProcess = victimProcesses
                    .stream()
                    .filter(p -> p.getProcessName().equals(process.getProcessName()))
                    .collect(Collectors.toSet());

            // 没有找到同名进程,判定所有被注入进程，都是正确的
            if (realVictimProcess.isEmpty()) {
                victimThreads.addAll(possibleVictimThreads);
            } else {// 找到了同名进程的处理情况,此时猜测注入进程注入的是跟自己同名的进程；从所有被注入进程中，过滤出同名的线程
                Set<etwThread> realVictimThreads = possibleVictimThreads
                        .stream()
                        .filter(etwThread -> realVictimProcess.contains(etwThread.getProcess()))
                        .collect(Collectors.toSet());
                victimThreads.addAll(realVictimThreads);
            }

            attacker2VictimThreads.putIfAbsent(process, victimThreads);

            for (etwThread thread : victimThreads) {
                victimThread2Attacker.put(thread, process);

                //victimProcess2Attacker.put(thread.getProcess(), process);
                Set<Process> attackers = victimProcess2Attackers.getOrDefault(thread.getProcess(), new TreeSet<>());
                victimProcess2Attackers.putIfAbsent(thread.getProcess(), attackers);
                attackers.add(process);

                logger.info("victimProcess2Attacker {}, {}", thread.getProcess(), process);

                Process victimProcess = thread.getProcess();
                if (victimProcess == null) {
                    continue;
                }
                int parentUuid = process.getUuid();
                EventForCS event = new EventForCS(EventType.INJECTION, clientId, victimProcess, timestamp, parentUuid, "", "");
                logger.info("injection: attacker {}, victim {}", process, thread);
                framework.addEvent(event);
            }

            victimThreads.forEach(t -> checkIfVictimThreadHasPhf(t, process));
        }
    }

    public void reCheck(Process process, long timestamp) {
        if (!attackers.contains(process)) {
            return;
        }

        List<Process> victimProcessList = attacker2VictimThreads.entrySet()
                .stream()
                .filter(e -> e.getKey().getUuid() == process.getUuid())
                .flatMap(e -> e.getValue().stream().map(p -> p.getProcess()))
                .distinct()
                .collect(Collectors.toList());

        for (Process victimProcess : victimProcessList) {
            EventForCS event = new EventForCS(EventType.INJECTION, clientId, victimProcess, timestamp, process.getUuid(), "", "");
            framework.addEvent(event);
        }
    }

    public Process getRealProcess(Process process, int threadId) {
        etwThread thread = new etwThread(process, threadId);
        return victimThread2Attacker.getOrDefault(thread, process);
    }

    public boolean isVictimThread(Process process, int threadId) {
        etwThread thread = new etwThread(process, threadId);

        if (victimThread2Attacker.containsKey(thread)) {
            return true;
        }

        /*
        // 一般情况下 该进程的父进程也会创建线程，并且会被报出PHF，此时打了标签，当真正的恶意线程因此没有打上标签
        if (possibleVictimThread2Attacker.containsKey(thread)) {
            return true;
        }
         */

        return false;
    }

    private void removePossibleAttacker(Process process) {
        if (attackers.contains(process)) {
            return;
        }

        while (possibleAttacker2VictimThreads.containsKey(process)) {
            possibleAttacker2VictimThreads.remove(process);
        }

        possibleVictimThread2Attacker.entrySet()
                .stream()
                .filter(entry -> entry.getValue().equals(process))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList())
                .forEach(possibleVictimThread2Attacker::remove);

        ProcessTable.removeProcess(clientId, process.getUuid());
    }

    private void removeAttacker(Process process) {
        removePossibleAttacker(process);
        victimThread2Attacker.entrySet()
                .stream()
                .filter(entry -> entry.getValue().equals(process))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList())
                .forEach(victimThread2Attacker::remove);

        while (attacker2VictimThreads.containsKey(process)) {
            attacker2VictimThreads.remove(process);
        }
        ProcessTable.removeProcess(clientId, process.getUuid());
    }

    private void removeVictimProcess(Process process) {
        // 被注入进程结束时立即清除
        if (victimProcess2Attackers.containsKey(process)) {
            while (victimProcess2Attackers.containsKey(process)) {
                victimProcess2Attackers.remove(process);
            }
        }

        // 当被注入的进程结束时立即清除
        possibleAttacker2VictimThreads.values().forEach(victimThreads -> {
            victimThreads.stream()
                    .filter(etwThread -> etwThread.getProcess().equals(process))
                    .collect(Collectors.toList())
                    .forEach(victimThreads::remove);
        });

        // 移除possibleAttacker,当被注入进程结束时
        possibleAttacker2VictimThreads
                .entrySet()
                .stream()
                .filter(entry -> entry.getValue().isEmpty())
                .map(entry -> entry.getKey())
                .collect(Collectors.toList())
                .forEach(possibleAttacker2VictimThreads::remove);

        // 当被注入的进程结束时立即清除
        possibleVictimThread2Attacker.keySet()
                .stream()
                .filter(etwThread -> etwThread.getProcess().equals(process))
                .collect(Collectors.toList())
                .forEach(possibleVictimThread2Attacker::remove);

    }

    public Set<Process> guessRealProcess(Process process) {
        return victimProcess2Attackers.get(process);
    }

    public void addProcessEnd(Process process) {
        // possibleAttacker 延迟移除
        // attackers 延迟移除

        // 注入进程结束时延迟结束
        if (possibleAttacker2VictimThreads.keySet().contains(process) && !attackers.contains(process)) {
            possibleAttackerDying.add(process);
        }

        if (attackers.contains(process)) {
            attackerDying.add(process);
        }

        if (possibleAttackerDying.size() > 3) {
            Process possibleAttacker = possibleAttackerDying.poll();
            removePossibleAttacker(possibleAttacker);
        }

        if (attackerDying.size() > 3) {
            Process attacker = attackerDying.poll();
            removeAttacker(attacker);
        }

        vimtimDying.add(process);
        if (vimtimDying.size() > 20) {
            Process victim = vimtimDying.poll();
            removeVictimProcess(victim);
        }
    }

    public Map<etwThread, Process> getPossibleVictimThread2Attacker() {
        return possibleVictimThread2Attacker;
    }

    public boolean isPossibleVictimThread(Process process, int threadId) {
        etwThread etwThread = new etwThread(process, threadId);

        return possibleVictimThread2Attacker.containsKey(etwThread);
    }

    public void addPossibleVictimThreadPhfLabel(Process process, int threadId, LabelForCS label) {
        etwThreadWrapper etwThreadWrapper = new etwThreadWrapper(process, threadId);
        CopyOnWriteArraySet<LabelForCS> phfs = possibleVictimThread2Phf.getOrDefault(etwThreadWrapper, new CopyOnWriteArraySet<>());
        possibleVictimThread2Phf.putIfAbsent(etwThreadWrapper, phfs);
        phfs.add(label);
    }

    private void checkIfVictimThreadHasPhf(etwThread etwThread, Process attacker) {
        etwThreadWrapper etwThreadWrapper = new etwThreadWrapper(etwThread);
        CopyOnWriteArraySet<LabelForCS> phfs = possibleVictimThread2Phf.get(etwThreadWrapper);
        if (phfs == null || phfs.isEmpty()) {
            return;
        }

        phfs.forEach(phf -> {
            if (phf == null) {
                return;
            }
            framework.addLabel(phf);
            triggerRemoteThreadPHFEvent(etwThread.getProcess(), etwThread.getThreadId(), phf.getTimestamp(), phf.getType());
        });

        possibleVictimThread2Phf.remove(etwThreadWrapper);
    }

    public void triggerRemoteThreadPHFEvent(Process process, int threadId, long timestamp, LabelType newLabelType) {
        // PT30标签特殊处理，同一个来源的PT30不会重复打，不同来源的PT30可以重复打

        // 如果是恶意线程，则回传给注入进程PT30
        Process attacker = getRealProcess(process, threadId);
        if (attacker.getUuid() == process.getUuid()) {
            // 没有被注入
            return;
        }

        triggerRemoteThreadPhfEvent(process, attacker, timestamp, newLabelType);
    }

    public void triggerRemoteThreadPhfEvent(Process victimProcess, Process attacker, long timestamp, LabelType newLabelType) {

        // 只回传一次
        ProcessNode attackerProcessNode = framework.getProcessMap().get(attacker.getUuid());
        if (attackerProcessNode == null) {
            return;
        }

        //==================
        // 递归回传PT1 A->B->c 的场景 B没有网络连接，需要把C的PT1递归回传给A
        transPT1(victimProcess, attacker, timestamp);
        //==================

        // 判断标签来源
        // 不同的来源可以重复打PT30
        boolean exist = attackerProcessNode.existLabelWithSource(victimProcess.getUuid(), LabelType.PT30);
        if (!exist) {

            EventForCS remoteThreadPhfEvent = new EventForCS(EventType.REMOTE_THREAD_PHF, clientId, victimProcess, timestamp, attacker.getUuid(), "", "");
            framework.addEvent(remoteThreadPhfEvent);

            // 给ProcessNode设置PT30的来源node
            attackerProcessNode.setLabelSource(victimProcess.getUuid(), LabelType.PT30);
        }

        // 递归回传,PT30只打一个
        // todo 被多次注入的情况如何处理？

        triggerRemoteThreadPHFEventGuessAttacker(attacker, timestamp);

        // 该进程跟注入进程已经回传过标签，此时需要根据注入关系找到第一个注入进程，刷新画图
        // Alusinus RAT v0.9 远程线程会一直报ScreenGrab，导致频繁画图 ；会根据上一次画图时间判断 是否需要刷新画图
        framework.findAttackerAndDrawGraph(attackerProcessNode);
    }

    private void triggerRemoteThreadPHFEventGuessAttacker(Process process, long timestamp) {
        Set<Process> attackers = guessRealProcess(process);
        if (attackers == null || attackers.isEmpty()) {
            return;
        }

        // 时间减少1s，为了能够上攻击图中显示出正确的注入顺序
        timestamp -= 1000000;

        long finalTimestamp = timestamp;
        long finalTimestamp1 = timestamp;
        attackers.forEach((attacker) -> {
            ProcessNode attackerProcessNode = framework.getProcessNode(attacker.getUuid());
            if (attackerProcessNode == null) {
                return;
            }

            // 判断标签来源
            // 不同的来源可以重复打PT30
            boolean exist = attackerProcessNode.existLabelWithSource(process.getUuid(), LabelType.PT30);

            if (!exist) {
                EventForCS remoteThreadPhfEvent = new EventForCS(EventType.REMOTE_THREAD_PHF, clientId, process, finalTimestamp, attacker.getUuid(), "", "");
                framework.addEvent(remoteThreadPhfEvent);
                // 给ProcessNode设置PT30的来源node
                attackerProcessNode.setLabelSource(process.getUuid(), LabelType.PT30);
            }

            transPT1(process, attacker, finalTimestamp1);

            triggerRemoteThreadPHFEventGuessAttacker(attacker, finalTimestamp);
        });
    }

    private void transPT1(Process victimProcess, Process attackerProcess, long timestamp) {
        ProcessNode attackerProcessNode = framework.getProcessMap().get(attackerProcess.getUuid());
        ProcessNode victimProcessNode = framework.getProcessMap().get(victimProcess.getUuid());
        if (attackerProcessNode == null || victimProcessNode == null) {
            return;
        }

        if (!attackerProcessNode.existLabel(LabelType.PT1)) {
            if (victimProcessNode != null) {
                if (victimProcessNode.existLabel(LabelType.PT1)) {
                    LabelForCS label = new LabelForCS(LabelType.PT1, clientId, attackerProcess.getUuid(), timestamp, "");
                    framework.addLabel(label);
                }
            }
        }
    }

    class etwThreadWrapper {
        etwThread etwThread;
        // 执行phf的服务端时间，该时间用于没有收到ProcessInjection时，判断超时的时间
        long time;


        public etwThreadWrapper(etwThread etwThread) {
            this.etwThread = etwThread;
            this.time = System.currentTimeMillis() / 1000;
        }

        public etwThreadWrapper(Process process, int threadId) {
            this.etwThread = new etwThread(process, threadId);
            this.time = System.currentTimeMillis() / 1000;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            etwThreadWrapper that = (etwThreadWrapper) o;
            return Objects.equal(etwThread, that.etwThread);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(etwThread);
        }
    }


}

