package NU.ETWRealTimeDetector.Framework;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

public class FileNodePersistJob implements Runnable {
    @Override
    public void run() {
        Map<String, DetectionFramework> clientId2instance = DetectionFramework.getClientId2instance();
        System.out.println("start run file node persist job.");
        try {
            FileUtils.forceMkdir(new File("cacheData"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        clientId2instance.entrySet().forEach(entry -> {
            //  if (entry.getValue().haveNewFileData()) {
            //      File fileLabelFile = new File("cacheData/" + entry.getKey() + "_fileNodeLabel");
            //      try {
            //          FileOutputStream fos = new FileOutputStream(fileLabelFile, false);
            //          fos.write(entry.getValue().getFileLabelBloomFilterBytes());
            //      } catch (Exception e) {
            //          e.printStackTrace();
            //      }

            //      File fileNodeFile = new File("cacheData/" + entry.getKey() + "_fileNode");
            //      try {
            //          FileOutputStream fos = new FileOutputStream(fileNodeFile, false);
            //          fos.write(entry.getValue().getFilePathBloomFilterBytes());
            //      } catch (Exception e) {
            //          e.printStackTrace();
            //      }
            //  }
        });
        System.out.println("file node persist job done.");
    }
}
