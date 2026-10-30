package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

import static java.util.Arrays.asList;

public abstract class Node implements Serializable {
    protected String clientId = "";

    private static final Logger logger = LoggerFactory.getLogger(Node.class);
    final BitSet labelList = new BitSet(LabelType.getSize());

    private boolean needsJudge = false;

    private boolean needsJudgeNow = false;

    private static List<LabelType> judgeLabels = asList(LabelType.PT12, LabelType.PT30, LabelType.PT18, LabelType.PT22, LabelType.PT2, LabelType.PT17);

    Node(String clientId) {
        this.clientId = clientId;
    }

    public void addLabel(LabelType labelType) {
        // 执行了敏感命令，强制judge,刷新画图
        if (judgeLabels.contains(labelType)) {
            this.needsJudge = true;
            this.needsJudgeNow = true;
        }
        if (!labelList.get(labelType.ordinal())) {
            if (needsJudge) {
                this.needsJudgeNow = true;
            } else {
                if (LabelType.isPhfLabel(labelType)) {
                    this.needsJudge = true;
                    this.needsJudgeNow = true;
                }
            }
        }
        if (this.getUuid() < 0) {
            logger.info("fileNodeAddLabel:" + this.getUuid() + " " + labelType + " -> " + this.getLabels());
        }

        labelList.set(labelType.ordinal());
    }

    public void setLabelList(String labelList) {
        if (labelList == null || labelList.length() == 0) {
            return;
        }

        String[] arr = labelList.split(",");

        Arrays.stream(arr)
                .map(LabelType::valueOf)
                .forEach(labelType -> this.labelList.set(labelType.ordinal()));
    }

    public boolean existLabel(LabelType labelType) {
        return labelList.get(labelType.ordinal());
    }

    public Set<LabelType> getLabels() {
        Set<LabelType> result = new HashSet<>();
        for (int i = 0; i < labelList.length(); i++) {
            if (labelList.get(i)) {
                result.add(LabelType.getLabelType(i));
            }
        }
        return result;
    }

    public String getClientId() {
        return clientId;
    }

    public abstract long getUuid();


    public boolean needsJudgeNow() {
        return needsJudgeNow;
    }

    public void turnOffJudgeNow() {
        needsJudgeNow = false;
    }
}
