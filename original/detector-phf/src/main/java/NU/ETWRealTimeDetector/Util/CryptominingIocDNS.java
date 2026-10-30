package NU.ETWRealTimeDetector.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CryptominingIocDNS {
    private Logger logger = LoggerFactory.getLogger(CryptominingIocDNS.class);
    private List<String> dnsList = new ArrayList<>();

    private static final CryptominingIocDNS instance = new CryptominingIocDNS("signatures/Crytomining/dns.txt");

    public static CryptominingIocDNS getInstance() {
        return instance;
    }

    private CryptominingIocDNS(String fileName) {
        try (Scanner scanner = new Scanner(new FileReader(fileName))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();

                if (line == null || line.isEmpty()) {
                    continue;
                }

                if (!dnsList.contains(line)) {
                    dnsList.add(line);
                }
            }
        } catch (Exception e) {
            logger.error("read cryptomining ioc dns failed", e);
        }

    }

    public boolean exist(String dns) {
        return dnsList.contains(dns);
    }

    public List<String> getDnsList() {
        return dnsList;
    }
}
