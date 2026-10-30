package NU.ETWRealTimeDetector.Util;

import java.util.HashMap;

public class MemoryInfo {


    public static HashMap<String, String> currentMemoryInfo() {

        // 虚拟机级内存情况查询
        long vmFree = 0;
        long vmUse = 0;
        long vmTotal = 0;
        long vmMax = 0;
        int byteToMb = 1024 * 1024;
        Runtime rt = Runtime.getRuntime();
        vmTotal = rt.totalMemory() / byteToMb;// 当前内存大小
        vmFree = rt.freeMemory() / byteToMb;// 可用内存大小
        vmMax = rt.maxMemory() / byteToMb;// 最大内存大小
        vmUse = vmTotal - vmFree;// 已使用内存大小

        //System.out.println("JVM内存已用的空间为：" + vmUse + " MB");
        //System.out.println("JVM内存的空闲空间为：" + vmFree + " MB");
        //System.out.println("JVM总内存空间为：" + vmTotal + " MB");
        //System.out.println("JVM总内存空间为：" + vmMax + " MB");

        HashMap<String, String> map = new HashMap<>(4);
        map.put("vmTotal", String.valueOf(vmTotal));
        map.put("vmFree", String.valueOf(vmFree));
        map.put("vmMax", String.valueOf(vmMax));
        map.put("vmUse", String.valueOf(vmUse));
        map.put("cpu", String.valueOf((int) Math.ceil(CPUMonitorCalc.getInstance().getProcessCpu())));

        return map;
    }

}
