package magicshield;

import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class ReadDataProtobufTest {

    @Test
    @Ignore
    public void test() {
        Random random = new Random();
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            Integer delay = random.nextInt(300);
            list.add(delay);
        }
        String startTimes = String.join(",", list.stream().map(i -> i.toString()).collect(Collectors.toList()));
        System.out.println(startTimes);
    }
}