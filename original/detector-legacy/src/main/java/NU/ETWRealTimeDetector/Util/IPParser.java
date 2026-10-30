package NU.ETWRealTimeDetector.Util;

import java.io.FileReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IPParser {
    static String ipPattern = "(?=(\\b|\\D))(((\\d{1,2})|(1\\d{1,2})|(2[0-4]\\d)|(25[0-5]))\\.){3}((\\d{1,2})|(1\\d{1,2})|(2[0-4]\\d)|(25[0-5]))(?=(\\b|\\D))";
    private static final String IP_ADDRESS = "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})";
    private static final Pattern addressPattern = Pattern.compile(IP_ADDRESS);

    private static HashSet<Integer> COMMONPORTS;

    public static String parseIpAddress(Long ipAddress) {
        return String.format("%d.%d.%d.%d",
                (ipAddress & 0xff),
                (ipAddress >> 8 & 0xff),
                (ipAddress >> 16 & 0xff),
                (ipAddress >> 24 & 0xff));
    }

    public static String longToIp(long i) {

        return ((i >> 24) & 0xFF) +
                "." + ((i >> 16) & 0xFF) +
                "." + ((i >> 8) & 0xFF) +
                "." + (i & 0xFF);

    }


    public static Long ipToLong(String ipStr) {
        List<String> list = Arrays.asList(ipStr.split("\\."));
        Collections.reverse(list);
        String[] ip = list.toArray(new String[list.size()]);
        return (Long.parseLong(ip[0]) << 24) + (Long.parseLong(ip[1]) << 16) + (Long.parseLong(ip[2]) << 8) + Long.parseLong(ip[3]);
    }

    public static long ipToLong2(String ipAddress) {

        long result = 0;

        String[] ipAddressInArray = ipAddress.split("\\.");

        for (int i = 3; i >= 0; i--) {

            long ip = Long.parseLong(ipAddressInArray[3 - i]);

            // left shifting 24,16,8,0 and bitwise OR

            // 1. 192 << 24
            // 1. 168 << 16
            // 1. 1 << 8
            // 1. 2 << 0
            result |= ip << (i * 8);

        }

        return result;
    }

    public static Integer parsePort(Integer port) {
        return (int) Math.floor(port / 256) + (port % 256) * 256;
    }

    public static boolean isCommonPort(Integer port) {
        if (COMMONPORTS == null) {
            COMMONPORTS = new HashSet<>();

            String file = "signatures/Port/WellknownPorts";
            try (Scanner scanner = new Scanner(new FileReader(file))) {
                while (scanner.hasNextLine()) {
                    String portStr = scanner.nextLine();
                    Integer _port = Integer.parseInt(portStr);
                    COMMONPORTS.add(_port);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return COMMONPORTS.contains(parsePort(port));
    }

    /*
    正则判断是否为IP
     */
    public static boolean isIpReg(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return Pattern.matches(ipPattern, ip);
    }

    /*
    简单判断是否为标准IP，目前Security登录事件里产生的IP，只有 - 或 127.0.0.1 或 正常IP
     */
    public static boolean isIp(String ip) {
        return ip != null && ip.length() > 5;
    }


    public static boolean isPublicIp(Long ipAddress) {
        boolean isPublicIp = true;
        int sigment1 = new Long(ipAddress & 0xff).intValue();
        int sigment2 = new Long(ipAddress >> 8 & 0xff).intValue();


        switch (sigment1) {
            case 10:
                isPublicIp = false;
                break;
            case 172:
                if (sigment2 >= 16 && sigment2 <= 31) {
                    isPublicIp = false;
                }
                break;
            case 192:
                if (sigment2 == 168) {
                    isPublicIp = false;
                }
                break;
            default:
                break;
        }
        return isPublicIp;
    }

    public static int toInteger(String address) {
        Matcher matcher = addressPattern.matcher(address);
        if (matcher.matches()) {
            return matchAddress(matcher);
        } else {
            throw new IllegalArgumentException("Could not parse [" + address + "]");
        }
    }

    public static boolean isBroadcastAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        if (!isIp(ip)) {
            return false;
        }

        int index = ip.lastIndexOf(".");
        if (index < 0) {
            return false;
        }

        String host = ip.substring(index + 1);
        if (host == null || host.isEmpty()) {
            return false;
        }

        return host.equals("255");
    }

    private static int matchAddress(Matcher matcher) {
        int addr = 0;
        for (int i = 1; i <= 4; ++i) {
            int n = (rangeCheck(Integer.parseInt(matcher.group(i)), 0, 255));
            addr |= ((n & 0xff) << 8 * (4 - i));
        }
        return addr;
    }

    private static int rangeCheck(int value, int begin, int end) {
        if (value >= begin && value <= end) { // (begin,end]
            return value;
        }

        throw new IllegalArgumentException("Value [" + value + "] not in range [" + begin + "," + end + "]");
    }

}
