package NU.ETWRealTimeDetector.Util;

import org.junit.Test;

import java.lang.management.ManagementFactory;
import java.util.Random;

import static org.junit.Assert.*;

public class CPUMonitorCalcTest {

    @Test
    public void getProcessCpu() throws InterruptedException {

        String name = ManagementFactory.getRuntimeMXBean().getName();
        System.out.println(name);
        System.out.println(CPUMonitorCalc.getInstance().getProcessCpu());

        for (int i = 0; i < 2; i++) {
            new Thread(() -> {
                while (true) {
                    long bac = 1000000;
                    bac = bac >> 1;
                }
            }).start();
            ;
        }
        Random random = new Random(0);
        while (true) {
            Thread.sleep(random.nextInt(10) * 1000);
            System.out.println(CPUMonitorCalc.getInstance().getProcessCpu());
        }
    }
}