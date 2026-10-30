package magicshield;

import org.junit.Ignore;
import org.junit.Test;
import org.xerial.snappy.Snappy;

import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit test for simple App.
 */
@Ignore
public class AppTest {
    /**
     * Rigorous Test.
     * @throws IOException
     */
    @Test
    public void testApp() throws IOException {
        String text = "fdsjafjdafjdsafjda";
        List<DataBlock> list = new ArrayList<>();

        DataBlock dataBlock = new DataBlock();
        dataBlock.sendTime = 1;
        dataBlock.eventCount = 1;
        dataBlock.dataSize = 1;
        dataBlock.data = Snappy.compress(text);

        for (int i = 0; i < 10; i++) {
            list.add(dataBlock);
        }

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("datablock.data"));
        oos.writeObject(list);
        oos.close();
        assertTrue(false);

    }

    public void deserializ() throws FileNotFoundException, IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("datablock.data"));
        Object obj = ois.readObject();
        List<DataBlock> list = (ArrayList<DataBlock>) obj;
        for (DataBlock dataBlock : list) {
            System.out.println(dataBlock);
        }

        ois.close();

    }
}
