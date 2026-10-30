package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Util.StringUtil;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class FileNodeTest {

    @Test
    public void isErrorPath() {
        FileNode a = new FileNode("\\Windows\\System32\\uDWM.dll", "test");
        FileNode b = new FileNode("\\??\\C:\\Program Files (x86)\\Common Files\\microsoft shared\\TigerKin\\xmsec64.sys", "test");
        FileNode c = new FileNode("\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.18362.235_none_5f42305c58dc2c51\\TiWorker.exe", "test");
        FileNode d = new FileNode("\\Users\\mayn\\AppData\\Local\\Fork\\gitInstance\\2.20.1\\mingw64\\libexec\\git-core\\git.exe", "test");
        FileNode e = new FileNode("\\Windows\\System32\\InputMethod\\CHS\\ChsIME.exe", "");
        FileNode ff = new FileNode("\\Program Files (x86)\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\OFFICE16\\SDXHelper.exe", "test");

        Map<String, FileNode> fileMap = new HashMap<>();
        fileMap.put(a.getFilePath(), a);
        fileMap.put(b.getFilePath(), b);
        fileMap.put(c.getFilePath(), c);
        fileMap.put(d.getFilePath(), d);
        fileMap.put(e.getFilePath(), e);
        fileMap.put(ff.getFilePath(), ff);

        List<String> rightPathList = new ArrayList<>();
        rightPathList.add("C:\\Windows\\System32\\uDWM.dll");
        rightPathList.add("C:\\Program Files (x86)\\Common Files\\microsoft shared\\TigerKin\\xmsec64.sys");
        rightPathList.forEach(rightPath -> {
            List<FileNode> list = fileMap.values().stream().filter(f -> !f.isPathRight()).filter(f -> rightPath.contains(f.getFilePath())).collect(Collectors.toList());
            list.forEach(f -> {
                fileMap.remove(f.getFilePath());
                f.setFilePath(rightPath, false);
                fileMap.put(f.getFilePath(), f);
            });
        });
    }
}