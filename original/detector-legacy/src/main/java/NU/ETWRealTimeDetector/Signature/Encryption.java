package NU.ETWRealTimeDetector.Signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Encryption {

    private static final Logger logger = LoggerFactory.getLogger(Encryption.class);
    // load clear signature, encrypt, then save
    public static void loadAndEncryptAndSave(String path) {
        File file = new File(path);
        try (Scanner scanner = new Scanner(new File("key.txt"))) {
            byte[] encoded = Files.readAllBytes(Paths.get(file.toURI()));

            String key = scanner.nextLine();
            //String key = "gs)ws71fa.a$6s4@"; // 128 bit key
            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            //byte[] encrypted = cipher.doFinal(text.getBytes());
            byte[] encrypted = cipher.doFinal(encoded);
            File encryptedFile = new File("encrypted/" + path);
            FileOutputStream fos = new FileOutputStream(encryptedFile);
            fos.write(encrypted);
            fos.close();
        } catch (Exception e) {
            logger.error("load and excrypt error", e);
        }
    }

    // load encrypted signature and decrypt it to clear signature
    public static List<String> loadAndDecrypt(String SIG_DIRECTORY, String[] PHF_NAME, String SIG_FILE_EXTENSION) {
        List<String> result = new ArrayList<String>();

        for (String phfName : PHF_NAME) {
            File file = new File(SIG_DIRECTORY + phfName + SIG_FILE_EXTENSION);
            try (Scanner scanner = new Scanner(new File("key.txt"))) {
                //String key = "gs)ws71fa.a$6s4@"; // 128 bit key
                String key = scanner.nextLine();
                Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                byte[] encrypted = Files.readAllBytes(Paths.get(file.toURI()));
                cipher.init(Cipher.DECRYPT_MODE, aesKey);
                String decrypted = new String(cipher.doFinal(encrypted));
                result.add(decrypted);
            } catch (Exception e) {
                logger.error("load and decrypt error", e);
            }
        }
        return result;
    }

    public static void walk(String directory) {
        File root = new File(directory);
        File[] list = root.listFiles();
        if (list == null) {
            return;
        }
        for (File f : list) {
            if (f.isDirectory()) {
                walk(f.getPath());
            }
            else {
                loadAndEncryptAndSave(f.getPath());
            }
        }
    }

    public static void main(String[] args) {
        walk(args[0]);
    }
}
