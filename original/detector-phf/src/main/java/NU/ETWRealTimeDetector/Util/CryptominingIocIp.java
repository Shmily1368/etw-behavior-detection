package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

public class CryptominingIocIp {
    private static final Logger logger = LoggerFactory.getLogger("cryptomining");
    private List<Long> ipList = new ArrayList<>();
    private HashMap<Long, String> ip2domainList = new HashMap<>();
    private static final boolean TURN_ON_DNS_Resolution = SysConfig.getBoolean("TurnOnDNSResolution", true);
    private static final ScheduledExecutorService pool = Executors.newSingleThreadScheduledExecutor();

    private static final CryptominingIocIp instance = new CryptominingIocIp("signatures/Crytomining/ip.txt");

    public static CryptominingIocIp getInstance() {
        return instance;
    }

    private CryptominingIocIp(String fileName) {
        try (Scanner scanner = new Scanner(new FileReader(fileName))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();

                if (line == null || line.isEmpty()) {
                    continue;
                }

                if (!ipList.contains(line)) {
                    ipList.add(IPParser.ipToLong(line.trim()));
                }
            }
        } catch (Exception e) {
            logger.error("read cryptomining ioc ip failed", e);
        }
        if (TURN_ON_DNS_Resolution) {
            pool.scheduleAtFixedRate(() -> {
                ip2domainList.clear();
                CryptominingIocDNS.getInstance().getDnsList().forEach(dns -> {
                    try {
                        InetAddress[] inetAddressArray = InetAddress.getAllByName(dns);
                        if (inetAddressArray.length <= 0) {
                            return;
                        }

                        logger.info(Arrays.toString(inetAddressArray));

                        Stream.of(inetAddressArray)
                                .filter(i -> !i.getHostAddress().equals("127.0.0.1"))
                                .map(i -> IPParser.ipToLong(i.getHostAddress()))
                                .forEach(ip -> ip2domainList.put(ip, dns));

                    } catch (UnknownHostException e) {
                        logger.warn(e.getMessage());
                    }
                });

            }, 0, 1, TimeUnit.DAYS);
        }
    }

    public boolean exist(Long ip) {
        return ipList.contains(ip) || ip2domainList.containsKey(ip);
    }

    public String getDnsOrIp(Long ip) {
        String dns = ip2domainList.get(ip);

        if (dns != null) {
            return dns;
        }

        return IPParser.parseIpAddress(ip);
    }

    public static void shutdown() {
        pool.shutdown();
    }
}
