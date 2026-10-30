/*
package NU.ETWRealTimeDetector.Detection.Detector;

import NU.ETWRealTimeDetector.ExtraDetectionFactors.ProcessInjection;
import NU.ETWRealTimeDetector.Framework.DetectionFramework;
import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Detection.DetectionThreadPool;
import NU.ETWRealTimeDetector.Cache.TraceKey;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Signature.SigKey;
import NU.ETWRealTimeDetector.Signature.Signature;
import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.Util.DumpEvent;
import NU.ETWRealTimeDetector.Util.IDumper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.*;

public class LCSDetector {
    private static Signature signature = Signature.getSignature();
    private static Map<SigKey, Set<Integer>> sigKey2ContainsApis = signature.getSignatureContainsApi();
    private static Map<SigKey, List<String>> sigKey2SignatureReadable = signature.getSignatureReadable();
    private static double matchProportion = SysConfig.getDouble("MatchProportion", 0.7);
    private static int apiDifference = SysConfig.getInteger("ApiDifference", 10);
    private static boolean matchAllSigs = SysConfig.getBoolean("MatchAllSigs", false);

    private static final Logger logger = LoggerFactory.getLogger(LCSDetector.class);

    private static Map<String, IDumper> clientId2Dumper = new LinkedHashMap<>();

    public static void detect(List<Integer> traceToDetect, TraceKey traceKey, long start) {
        Iterator<Map.Entry<SigKey, List<Integer>>> it = signature.getSignatures().entrySet().iterator();
        int[][] score = DetectionThreadPool.getScoreArray();
        while (it.hasNext()) {
            Map.Entry<SigKey, List<Integer>> entry = it.next();
            SigKey sigKey = entry.getKey();
            Set<Integer> usefulApi = sigKey2ContainsApis.get(sigKey);
            List<String> signatureReadable = sigKey2SignatureReadable.get(sigKey);

            List<Integer> finalApiNameListInInt = new ArrayList<>(traceToDetect.size());

            for (Integer api : traceToDetect) {
                if (usefulApi.contains(api)) {
                    finalApiNameListInInt.add(api);
                }
            }
            if (finalApiNameListInInt.size() == 0) {
                continue;
            }
            Set<Integer> finalApiNameSetInInt = new HashSet<>(finalApiNameListInInt);
            finalApiNameSetInInt.retainAll(usefulApi);

            List<Integer> sigList = entry.getValue();
            for (Integer i = 1; i != sigList.size() + 1; i++){
                for (Integer j = 1; j != finalApiNameListInInt.size() + 1; j++){
                    if ((sigList.get(i-1).equals(finalApiNameListInInt.get(j-1)))) {
                        score[i][j] = score[i-1][j-1]+1;
                    }
                    else {
                        score[i][j] = score[i-1][j-1];
                    }
                    score[i][j] = Math.max(score[i][j],Math.max(score[i][j-1],score[i-1][j]));
                }
            }
            int lcsScore = score[sigList.size()][finalApiNameListInInt.size()];
            int signatureSize = sigList.size();
            double matchProp= 1.0 * lcsScore / signatureSize;

            if (matchProp >= matchProportion) {
                Set<Integer> filteredApiNameSet = new HashSet<>(traceToDetect);
                Set<Integer> sigSet = new HashSet<>(entry.getValue());
                int difference = filteredApiNameSet.size() - sigSet.size();

                try (BufferedWriter bw = new BufferedWriter(new FileWriter("fullreport.txt", true))) {
                    bw.write(String.format("%s %s %f %d\n", traceKey, sigKey, matchProp, difference));
                } catch (Exception e) {
                    logger.error("bw error", e);
                }

                if (difference <= apiDifference) {
                    logger.info(traceKey.toString() + "======================================================Detected=====================================================" + sigKey.toString());
                    record(traceKey, sigKey, start, signatureReadable);
                    sendLabelToFramework(traceKey, sigKey, start);
                    if (!matchAllSigs) {
                        break;
                    }
                }
            }

            if (matchProp >= 0.75 && sigKey.getPhfName().contains("injection")) {
                ProcessInjection processInjection = ProcessInjection.getInstance(traceKey.getClientID());
                processInjection.addPossibleInjection(traceKey.getProcess());
            }
        }
        DetectionThreadPool.returnScoreArray(score);
    }

    private static void record(TraceKey traceKey, SigKey sigKey, long traceStartTime, List<String> signature) {
        String clientId = traceKey.getClientID();
        Map argument = new HashMap();
        argument.put("TraceKey", traceKey.toString());
        argument.put("SigKey", sigKey.toString());
        argument.put("Signature", signature);
        IDumper dumper;
        if ((dumper = clientId2Dumper.get(clientId)) == null) {
            dumper = new DumpEvent(clientId);
            clientId2Dumper.put(clientId, dumper);
            if (clientId2Dumper.size() > 5) {
                Iterator it = clientId2Dumper.entrySet().iterator();
                it.next();
                it.remove();
            }
        }
        dumper.writeToDump("PhfReport.txt", traceKey.getProcess().getProcessId(), traceStartTime, argument);
    }

    private static void sendLabelToFramework(TraceKey traceKey, SigKey sigKey, long traceStartTime) {
        ProcessInjection processInjection = ProcessInjection.getInstance(traceKey.getClientID());
        LabelForCS label = new LabelForCS();
        Process realProcess = processInjection.getRealProcess(traceKey.getProcess(), traceKey.getTid());
        //logger.info("lcsdetected, fake {}, real {}", traceKey.getProcess(), realProcess);
        label.uuid = realProcess.getUuid();
        label.pid = realProcess.getProcessId();
        label.timeStamp = traceStartTime;
        label.stringField = traceKey.getProcess().getProcessName();
        if (sigKey.getPhfName().contains("audio")) {
            label.labelName = "PT5";
        } else if (sigKey.getPhfName().contains("download")) {
            label.labelName = "PT6";
        } else if (sigKey.getPhfName().contains("keylogger")) {
            label.labelName = "PT7";
        } else if (sigKey.getPhfName().contains("desktop")) {
            label.labelName = "PT8";
        } else if (sigKey.getPhfName().contains("shell")) {
            label.labelName = "PT9";
        } else if (sigKey.getPhfName().contains("grab")) {
            label.labelName = "PT16";
        } else {
            return;
        }
        DetectionFramework framework = DetectionFramework.getInstance();
        framework.addLabel(label);
    }
}

*/
