package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class VisibleWindow {
    private static final Logger logger = LoggerFactory.getLogger(VisibleWindow.class);
    private static final Logger visibleWindowLogger = LoggerFactory.getLogger("visiblewindow");
    private static Map<String, VisibleWindow> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    public static VisibleWindow getInstance(String clientId) {
        VisibleWindow visibleWindow = clientId2Instance.get(clientId);
        if (visibleWindow == null) {
            visibleWindow = new VisibleWindow(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, visibleWindow);
        return visibleWindow;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private String clientId;
    private int screenRightBoundary = 0;
    private int screenBottomBoundary = 0;

    private Set<Integer> processHasVisibleButCantFindInProcessTable = new HashSet<>();

    public VisibleWindow(String clientId) {
        this.processTable = ProcessTable.getInstance(clientId);
        this.framework = DetectionFramework.getInstance(clientId);
        this.dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    public void addWindowRecord(int processId, int left, int top, int right, int bottom, int visible, int appearInTaskbar, long timestamp) {
        // dump start
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("left", left);
            arguments.put("top", top);
            arguments.put("right", right);
            arguments.put("bottom", bottom);
            arguments.put("visible", visible);
            arguments.put("taskbar", appearInTaskbar);
            dumpEvent.writeToDump("VisibleWindow", processId, timestamp, arguments);
        }
        // dump end

        if (right - left < 2 || bottom - top < 2) {
            return;
        }

        boolean _visible = visible(left, top, right, bottom);
        visibleWindowLogger.info("clientId:{} pid:{} left:{} top:{} right:{} bottom:{} visible:{} appearInTaskbar:{} timestamp:{} screenRightBoundary:{} screenBottomBoundary:{} useDefaultScreenBoundary:{} Visible:{} ",
                clientId,
                processId,
                left,
                top,
                right,
                bottom,
                visible,
                appearInTaskbar,
                timestamp,
                screenRightBoundary,
                screenBottomBoundary,
                screenBottomBoundary == 0 && screenBottomBoundary == 0,
                _visible
        );


        if (_visible) {
            List<Process> processList = processTable.getCurrentAliveProcessList(processId);
            if (processList != null && !processList.isEmpty()) {
                for (Process process : processList) {
                    LabelForCS label = new LabelForCS(LabelType.PF3, clientId, process.getUuid(), timestamp, "");
                    framework.addLabel(label);
                    framework.cancelIfReport(process);
                }
            } else {
                processHasVisibleButCantFindInProcessTable.add(processId);
                if (processHasVisibleButCantFindInProcessTable.size() > 5) {
                    logger.warn("processHasVisibleButCantFindInProcessTable size too large :" + processHasVisibleButCantFindInProcessTable.size());
                }
            }
        }
    }

    public void setScreenBoundary(int right, int bottom) {
        // dump start
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("RightBoundary", right);
            arguments.put("BottomBoundary", bottom);
            dumpEvent.writeToDump("ScreenBoundary", 0, 0, arguments);
        }
        // dump end
        screenRightBoundary = right;
        screenBottomBoundary = bottom;
    }

    public void newProcessStarted(Process process) {
        if (processHasVisibleButCantFindInProcessTable.contains(process.getProcessId())) {
            LabelForCS label = new LabelForCS(LabelType.PF3, clientId, process.getUuid(), process.getStartTime(), "");
            framework.addLabel(label);
            processHasVisibleButCantFindInProcessTable.remove(process.getProcessId());
        }
    }

    public boolean visible(int left, int top, int right, int bottom) {
        int tempScreenBottomBoundary = screenBottomBoundary;
        int tempScreenRightBoundary = screenRightBoundary;

        if (left < 0 && right < 0 && top < 0 && bottom < 0) {
            return true;
        }

        if (screenBottomBoundary == 0 && screenRightBoundary == 0) {
            // 丢失了pid为0 的VisibleWindowInfo事件
            tempScreenBottomBoundary = 3840;
            tempScreenRightBoundary = 2160;
        }


        if (bottom > 0 && top < tempScreenBottomBoundary && right > 0 && left < tempScreenRightBoundary) {
            return true;
        }

        return false;
    }
}
