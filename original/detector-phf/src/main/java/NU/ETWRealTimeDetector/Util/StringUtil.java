package NU.ETWRealTimeDetector.Util;

import org.apache.commons.lang3.StringUtils;

import java.nio.file.Path;

public class StringUtil {

    public static boolean isPathRight(String filePath) {
        if (filePath != null && filePath.length() > 1 && filePath.indexOf(":") == 1) {
            return true;
        }
        return false;
    }
}
