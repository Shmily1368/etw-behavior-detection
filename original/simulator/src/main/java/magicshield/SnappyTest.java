package magicshield;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.zip.GZIPOutputStream;

import org.xerial.snappy.Snappy;

/**
 * SnappyTest
 */
public class SnappyTest {

    public static void main(String[] args) throws IOException {
        int i = 0;

        File file = new File("new.data.compressed");
        FileOutputStream fos = new FileOutputStream(file);
        GZIPOutputStream gzip = new GZIPOutputStream(fos);
        try (Scanner scanner = new Scanner(new FileReader("new.data"))) {
            while (scanner.hasNextLine()) {
                i++;
                //byte[] bytes = Snappy.compress(scanner.nextLine());
                gzip.write(scanner.nextLine().getBytes());
                if (i % 10000 == 0) {
                    System.out.println(i);
                    gzip.flush();
                }
            }
        }
        fos.flush();
        gzip.flush();
        gzip.close();
        fos.close();
    }
}