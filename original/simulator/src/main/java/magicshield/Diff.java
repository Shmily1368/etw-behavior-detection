package magicshield;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import com.google.gson.Gson;

/**
 * Diff
 */
public class Diff {

    public static void main(String[] args) throws FileNotFoundException {
        List<String> list = new ArrayList<>();
        try (Scanner scanner = new Scanner(new FileReader("timestamp"))) {
            while (scanner.hasNextLine()) {
                list.add(scanner.nextLine());
            }
        }

        int i = 1;
        try (Scanner scanner = new Scanner(new FileReader("2019-06-26-10-25-34.out"))) {

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                Map<String, Object> map = JsonToMap.toMap(line);
                String timestamp = map.get("TimeStamp").toString();
                if (!list.contains(timestamp)) {
                    System.out.println(line);
                }

                i++;
            }

        } catch (Exception e) {
        }

        System.out.println(list.size());
        System.out.println("over.");

    }
}