package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.Util.snapshot.Snapshot;
import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.*;

public class SnapshotTest {

    @Test
    public void getFileNodeByteArray() {
        HashMap<String, byte[]> map = Snapshot.getFileNodeByteArray("");
        assertNotNull(map);
    }
}