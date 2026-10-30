package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.Process.Process;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ProcessNode extends Node {
    private Process process;

    private ProcessNode parentNode;
    private List<ProcessNode> childNodes = new ArrayList<>();

    private BitSet alreadyReportedPhfs;
    private BitSet alreadyMonitorReportedLabels;

    // 保存每个标签的来源
    // 有部分标签是可以重复打的，例如PT30，不同来源的PT30可以重复打，这里保存传递的源ProcessNode，用于判断是否打了PT30标签
    private List<String> relationship = new ArrayList<>();

    private static Neo4jClient neo4jClient = Neo4jClient.getInstance();

    public ProcessNode(Process process) {
        super(process.getClientId());
        this.process = process;
    }

    public Process getProcess() {
        return process;
    }

    @Override
    public long getUuid() {
        return process.getUuid();
    }

    public ProcessNode getParentNode() {
        return parentNode;
    }

    public List<ProcessNode> getChildNodes() {
        return childNodes;
    }

    public void setPhfToAlreadyReported(LabelType labelType) {
        if (alreadyReportedPhfs == null) {
            alreadyReportedPhfs = new BitSet(LabelType.getPhfSize());
        }
        alreadyReportedPhfs.set(LabelType.getPhfIndex(labelType));
    }

    public void setLabelToAlreadyReportedInMonitor(LabelType labelType) {
        if (alreadyMonitorReportedLabels == null) {
            alreadyMonitorReportedLabels = new BitSet(labelType.ordinal());
        }
        alreadyMonitorReportedLabels.set(labelType.ordinal());
    }

    public boolean checkIfPhfHasBeenReported(LabelType labelType) {
        if (alreadyReportedPhfs == null) {
            alreadyReportedPhfs = new BitSet(LabelType.getPhfSize());
        }
        return alreadyReportedPhfs.get(LabelType.getPhfIndex(labelType));
    }

    public boolean checkIfLabelHasBeenMonitorReported(LabelType labelType) {
        if (alreadyMonitorReportedLabels == null) {
            alreadyMonitorReportedLabels = new BitSet(labelType.ordinal());
        }
        return alreadyMonitorReportedLabels.get(labelType.ordinal());
    }

    public boolean existLabelWithSource(int uuid, LabelType labelType) {
        String key = String.format("%d_%s", uuid, labelType.name());

        return existLabel(labelType) && relationship.contains(key);
    }

    public void setLabelSource(int uuid, LabelType labelType) {
        String key = String.format("%d_%s", uuid, labelType.name());
        if (!relationship.contains(key)) {
            relationship.add(key);
        }
    }

    public void setParentNode(ProcessNode parentNode, boolean affectNeo4j) {
        ProcessNode previousParentNode = this.parentNode;
        this.parentNode = parentNode;

        if (affectNeo4j) {
            if (previousParentNode == null || (previousParentNode != null && previousParentNode.getProcess().getProcessName().equals("root"))) {
                //neo4jClient.deleteNodeRelation(clientId, this.parentNode, this, EventType.PROCESS_START);
                neo4jClient.addProcessRelation(clientId, parentNode, this, EventType.PROCESS_START, process.getStartTime() / 1000000L);
            }
        }
    }

    @Override
    public String toString() {
        return process.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof ProcessNode))
            return false;

        ProcessNode that = (ProcessNode) o;

        return process != null ? process.equals(that.process) : that.process == null;
    }

    @Override
    public int hashCode() {
        return process != null ? process.hashCode() : 0;
    }
}
