package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import NU.ETWRealTimeDetector.IPC.Reporter;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Util.CryptominingIocDNS;
import NU.ETWRealTimeDetector.Util.CryptominingIocIp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Cryptomining {
    private static final Logger logger = LoggerFactory.getLogger("cryptomining");
    private static Map<String, Cryptomining> clientId2Instance = new HashMap<>();
    private static final CryptominingIocIp cryptoMiningIocIp = CryptominingIocIp.getInstance();
    private static final CryptominingIocDNS cryptoMiningIocDNS = CryptominingIocDNS.getInstance();

    public static Cryptomining getInstance(String clientId) {
        Cryptomining cryptomining = clientId2Instance.get(clientId);
        if (cryptomining == null) {
            cryptomining = new Cryptomining(clientId);
        }
        clientId2Instance.put(clientId, cryptomining);

        return cryptomining;
    }

    private String clientId;
    private final List<Integer> dnsMinerUuids = new ArrayList<>();
    private final List<Integer> ipMinerUuids = new ArrayList<>();

    public Cryptomining(String clientId) {
        this.clientId = clientId;
    }

    public void checkIp(Process process, Long ip, Long timestamp) {
        if (cryptoMiningIocIp.exist(ip) && !ipMinerUuids.contains(process.getUuid())) {
            // async report
            String ioc = cryptoMiningIocIp.getDnsOrIp(ip);
            if (process.hasProcessName()) {
                ipMinerUuids.add(process.getUuid());
                Reporter.reportCryptoMining(clientId, process, ioc, System.currentTimeMillis() / 1000);
            }
        }
    }

    public void checkDNS(Process process, String dns, Long timestamp) {
        if (cryptoMiningIocDNS.exist(dns)) {
            if (!dnsMinerUuids.contains(process.getUuid())) {
                //async report
                if (process.hasProcessName()) {
                    dnsMinerUuids.add(process.getUuid());
                    Reporter.reportCryptoMining(clientId, process, dns, System.currentTimeMillis() / 1000);
                }
            }
        }
    }
}
