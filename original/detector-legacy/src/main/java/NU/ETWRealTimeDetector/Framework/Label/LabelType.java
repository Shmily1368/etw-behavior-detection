package NU.ETWRealTimeDetector.Framework.Label;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public enum LabelType {
    PT1,
    PT2,
    PT3,
    PT4,
    PT5,
    PT6,
    PT7,
    PT8,
    PT9,
    PT10,
    PT11,
    PT12,
    PT13,
    PT14,
    PT15,
    PT16,
    PT17,
    PT18,
    PT181,
    PT182,
    PT183,
    PT184,
    PT19,
    PT20,
    PT21,
    PT22,
    PT23,
    PT24,
    PT25,
    PT26,
    PT27,
    PT28,
    // 远程线程做了PHF
    PT30,
    // 注入相关的label 40 开头
    PT40,
    PT41,

    // 注入lsass.exe
    PT42,
    // 内网端口扫描
    PT43,
    // 代表脚本进程
    PT50,

    // 恶意线程访问了敏感文件
    PT52,

    PT65,
    PT67,
    PT68,
    PT69,
    PT72,
    PT76,
    PT100,
    PT101,
    // 该程序是一个含有已知漏洞的程序
    PT105,

    PF1,
    PF2,
    PF3,
    PF4,

    FT1,
    FT2,
    FT3,
    FT4,
    FT5,
    FT6,
    FT7,
    FT8,
    FT9,
    FT23,
    FT24,
    FT25,
    FT26;

    private static EnumSet<LabelType> processLabels = EnumSet.of(PT1, PT2, PT3, PT4, PT5, PT6, PT7, PT8, PT9, PT10, PT11, PT12, PT13, PT14, PT15, PT16, PT17, PT18, PT19, PT20, PT21, PT22, PT23, PT24, PT25, PT26, PT42, PT100, PT101, PF1, PF2, PF3, PF4);
    public static EnumSet<LabelType> fileLabels = EnumSet.of(FT1, FT2, FT3, FT4, FT5, FT6, FT7, FT8, FT9, FT23, FT24, FT25);

    private static EnumSet<LabelType> phfLabels = EnumSet.noneOf(LabelType.class);
    private static Map<LabelType, Integer> phfLabel2Index = new HashMap<>();

    static boolean isProcessLabel(LabelType type) {
        return processLabels.contains(type);
    }

    static boolean isFileLabel(LabelType type) {
        return fileLabels.contains(type);
    }

    public static void addPhfLabel(LabelType type) {
        phfLabel2Index.putIfAbsent(type, phfLabels.size());
        phfLabels.add(type);
    }

    public static boolean isPhfLabel(LabelType type) {
        return phfLabels.contains(type);
    }

    private static Map<Integer, LabelType> ordinal2LabelType = new HashMap<>();


    static {
        LabelType[] values = LabelType.values();
        size = values.length;
        for (LabelType labelType : values) {
            ordinal2LabelType.put(labelType.ordinal(), labelType);
        }
    }

    private static int size;

    public static int getSize() {
        return size;
    }

    public static LabelType getLabelType(int ordinal) {
        return ordinal2LabelType.get(ordinal);
    }

    public static int getPhfIndex(LabelType labelType) {
        return phfLabel2Index.getOrDefault(labelType, -1);
    }

    public static int getPhfSize() {
        return phfLabel2Index.size();
    }

}
