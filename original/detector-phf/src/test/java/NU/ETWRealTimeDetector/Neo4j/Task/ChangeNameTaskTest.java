package NU.ETWRealTimeDetector.Neo4j.Task;

import org.junit.Test;

import static org.junit.Assert.*;

public class ChangeNameTaskTest {

    @Test
    public void count() {
        String path1 = "c:\\\\users\\\\lenovo\\\\appdata\\\\locallow\\\\sogoupy\\\\sgim_url.bin.sgbak1";
        String path2 = "c:\\\\users\\\\lenovo\\\\appdata\\\\locallow\\\\sogoupy\\\\sgim_url.bin.sgbak2";
        String path3 = "c:\\\\users\\\\lenovo\\\\appdata\\\\locallow\\\\sogoupy\\\\sgim_url.bin.sgbak3";
        String path4 = "c:\\\\users\\\\lenovo\\\\appdata\\\\locallow\\\\sogoupy\\\\sgim_url.bin.sgbak4";

        StringBuilder builder = new StringBuilder();
        builder.append(path1);
        builder.append(ChangeNameTask.separationCharacter);
        builder.append(path2);
        builder.append(ChangeNameTask.separationCharacter);
        builder.append(path3);
        builder.append(ChangeNameTask.separationCharacter);
        builder.append(path4);
        builder.append(ChangeNameTask.separationCharacter);


        int count = ChangeNameTask.count(builder.toString(), ChangeNameTask.separationCharacter);
        assertTrue(count == 4);
        ChangeNameTask.prune(builder);

        count = ChangeNameTask.count(builder.toString(), ChangeNameTask.separationCharacter);
        assertTrue(count == 3);


    }
}