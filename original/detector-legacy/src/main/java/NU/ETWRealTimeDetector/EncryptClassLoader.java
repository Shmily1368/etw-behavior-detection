package NU.ETWRealTimeDetector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.Key;
import java.util.Scanner;

public class EncryptClassLoader extends ClassLoader {
    private final Logger logger = LoggerFactory.getLogger(EncryptClassLoader.class);
    public EncryptClassLoader(ClassLoader parent) {
        super(parent);
    }

    private Class getClass(String name) throws ClassNotFoundException {
        String file = name.replace('.', File.separatorChar) + ".class";
        byte[] b = null;
        try {
            // This loads the byte code data from the file
            b = loadClassFileData(file);
            b = decrypt(b);
            // defineClass is inherited from the ClassLoader class
            // that converts byte array into a Class. defineClass is Final
            // so we cannot override it
            Class c = defineClass(name, b, 0, b.length);
            resolveClass(c);
            return c;
        } catch (IOException e) {
            logger.error("IOException", e);
            return null;
        }
    }

    @Override
    public Class loadClass(String name) throws ClassNotFoundException {
        if (name.startsWith("NU.ETWRealTimeDetector")) {
            return getClass(name);
        }
        return super.loadClass(name);
    }

    private byte[] loadClassFileData(String name) throws IOException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream(name);
        int size = stream.available();
        byte buff[] = new byte[size];
        DataInputStream in = new DataInputStream(stream);
        in.readFully(buff);
        in.close();
        return buff;
    }

    private static byte[] decrypt(byte[] encrypted) {
        Logger logger = LoggerFactory.getLogger(EncryptClassLoader.class);
        try (Scanner scanner = new Scanner(new File("key.txt"))) {
            String key = scanner.nextLine();
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            logger.error("decrypt error", e);
            System.exit(1);
        }
        return null;
    }

}
