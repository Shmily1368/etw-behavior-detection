package NU.ETWRealTimeDetector.Util;

import org.apache.commons.codec.digest.Md5Crypt;
import org.junit.Test;

import static org.junit.Assert.*;

public class MD5Test {

    @Test
    public void hashKeyForDisk() {
        String str = "123456";
        String h2 = MD5.hashKeyForDisk(str);
    }
}