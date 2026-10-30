package NU.ETWRealTimeDetector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;


public class SysConfig {
    private static Properties configuration = new Properties();
    private static Logger logger = LoggerFactory.getLogger(SysConfig.class);
    private static String env_prefix = "detector_";

    public SysConfig() {
    }

    public static Properties getProperties() {
        return configuration;
    }

    public SysConfig(String fileName) throws IOException {
        load(fileName);
    }

    public static void load(String fileName) throws IOException {
        try {
            configuration.loadFromXML(SysConfig.class.getClassLoader().getResourceAsStream(fileName));

            System.out.println("env_prefix:" + env_prefix);
            for (Object key : configuration.keySet()) {
                String envValue = System.getenv(env_prefix + key.toString());
                if (envValue != null && envValue.length() > 0) {
                    configuration.setProperty(key.toString(), envValue);
                }

                System.out.println(key.toString() + ":" + configuration.getProperty(key.toString()));
            }

        } catch (IOException e) {
            logger.error("load xml error", e);
            String message = "I/O error while reading configuration file "
                    + fileName;
            throw new IOException(message);
        }
    }

    public static Integer getInteger(String key, Integer defaultValue) {
        String ret = configuration.getProperty(key);
        if (ret == null) {
            return defaultValue;
        }
        try {
            return Integer.valueOf(ret);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    public static Integer getInteger(String key) {
        return getInteger(key, null);
    }

    public static Double getDouble(String key, Double defaultValue) {
        try {
            return Double.valueOf(configuration.getProperty(key));
        } catch (Exception e) {
            return defaultValue;
        }
    }

    public static Double getDouble(String key) {
        return getDouble(key, null);
    }

    public static void setInteger(String key, Integer value) {
        configuration.setProperty(key, value.toString());
    }

    public static String getString(String key, String defaultValue) {
        String result = configuration.getProperty(key);
        return result == null ? defaultValue : result;
    }

    public static String getString(String key) {
        return getString(key, null);
    }

    public static void setString(String key, String value) {
        configuration.setProperty(key, value);
    }

    public static Boolean getBoolean(String key, Boolean defaultValue) {
        String value = configuration.getProperty(key);
        return value == null ? defaultValue : Boolean.valueOf(value);
    }

    public static Boolean getBoolean(String key) {
        return getBoolean(key, null);
    }

    public static void setBoolean(String key, Boolean value) {
        configuration.setProperty(key, value.toString());
    }

}
