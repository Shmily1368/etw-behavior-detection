package NU.ETWRealTimeDetector.ExtraDetectionFactors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class FileFromUDisk {
    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);
    private static Map<String, FileFromUDisk> clientId2Instance= new HashMap<>();

    private String clientId;
    private Set<String> uDiskVolumeId = new HashSet<>();

    public static FileFromUDisk getInstance(String clientId) {
        FileFromUDisk instance = clientId2Instance.get(clientId);
        if (instance == null) {
            instance = new FileFromUDisk(clientId);
        }
        clientId2Instance.putIfAbsent(clientId, instance);
        return instance;
    }

    private FileFromUDisk(String clientId) {
        this.clientId = clientId;
    }

    public static void removeClient(String clientId) {
        clientId2Instance.remove(clientId);
    }


    public void addUDiskVolumeId(String volumeId) {
        uDiskVolumeId.add(volumeId.toLowerCase());
    }

    public boolean checkIfFileFromUDisk(String fileName) {
        for (String volumeId : uDiskVolumeId) {
            if (fileName.toLowerCase().startsWith(volumeId)) {
                return true;
            }
        }
        return false;
    }
}
