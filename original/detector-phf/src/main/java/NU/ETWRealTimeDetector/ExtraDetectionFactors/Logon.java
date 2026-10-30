package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.EventRecord.LogonType;
import NU.ETWRealTimeDetector.Process.Process;

public class Logon {
    public void checkLogon(Process process, LogonType logonType, String targetUserName, Long timestamp,boolean success) {
        if (logonType.equals(LogonType.Service)) {
            // logonType为5是程序启动时会产生，由于数量较多，不处理
            return;
        }




    }
}
