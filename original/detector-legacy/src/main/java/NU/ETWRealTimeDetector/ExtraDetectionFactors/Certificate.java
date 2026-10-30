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

import java.util.HashMap;
import java.util.Map;

public class Certificate {
    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);
    private static Map<String, Certificate> clientId2Instance = new HashMap<>();
    private static final boolean TURN_ON_DUMP = SysConfig.getBoolean("DumpExtraDetectionFactors", false);

    public static Certificate getInstance(String clientId) {
        Certificate certificate = clientId2Instance.get(clientId);
        if (certificate == null) {
            certificate = new Certificate(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, certificate);
        return certificate;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }

    private ProcessTable processTable;
    private DetectionFramework framework;
    private IDumper dumpEvent;
    private String clientId;

    public Certificate(String clientId) {
        processTable = ProcessTable.getInstance(clientId);
        framework = DetectionFramework.getInstance(clientId);
        dumpEvent = new DumpEvent(clientId);
        this.clientId = clientId;
    }

    public Process addProcessIdAndFileNameAndIfHasCertificate(int processId, String fileName, int certificateState, long timestamp) {
        boolean hasCertificate = certificateState == 1;
        // dump start
        if (TURN_ON_DUMP) {
            Map arguments = new HashMap();
            arguments.put("FileName", fileName);
            arguments.put("HasCertificate", hasCertificate);
            dumpEvent.writeToDump("Certificate", processId, timestamp, arguments);
        }
        // dump end

        Process process = processTable.getProcessOrCreateOneIfNotExist(processId, timestamp);
        if (!hasCertificate) {
            if (certificateState == 0) {
                LabelForCS label = new LabelForCS(LabelType.FT2, clientId, timestamp, fileName);
                framework.addLabel(label);
            }

            if (certificateState == 3) {// 证书过期
                LabelForCS label = new LabelForCS(LabelType.FT23, clientId, timestamp, fileName);
                framework.addLabel(label);
            }

            if (certificateState == 4) {// 非可信证书
                LabelForCS label = new LabelForCS(LabelType.FT24, clientId, timestamp, fileName);
                framework.addLabel(label);
            }

            if (certificateState == 5) {// 证书被篡改
                LabelForCS label = new LabelForCS(LabelType.FT25, clientId, timestamp, fileName);
                framework.addLabel(label);
            }

            if (certificateState == 6) {// 证书被颁发者撤销
                LabelForCS label = new LabelForCS(LabelType.FT26, clientId, timestamp, fileName);
                framework.addLabel(label);
            }
        }
        if (fileName.equals(process.getProcessName()) && !hasCertificate) {
            LabelType labelType = LabelType.PT18;
            if (certificateState == 3) {
                labelType = LabelType.PT181;
            } else if (certificateState == 4) {
                labelType = LabelType.PT182;
            } else if (certificateState == 5) {
                labelType = LabelType.PT183;
            } else if (certificateState == 6) {
                labelType = LabelType.PT184;
            }
            LabelForCS label = new LabelForCS(labelType, clientId, process.getUuid(), timestamp, fileName);
            framework.addLabel(label);
            // 如果文件是从网络下载的，并且没有数字签名，则打PT4标签，代表 加载了来自网络的，没有证书的镜像
            //framework.addLabel(new LabelForCS(LabelType.PT4, clientId, process.getUuid(), timestamp, fileName));
        }
        return process;
    }
}
