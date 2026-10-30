package NU.ETWRealTimeDetector;

import java.lang.reflect.Method;

public class FakeMain {
    public static void main(String[] args) throws Exception {
        EncryptClassLoader loader = new EncryptClassLoader(FakeMain.class.getClassLoader());
        String progArgs[] = new String[args.length - 1];
        System.arraycopy(args, 1, progArgs, 0, progArgs.length);
        Class clas = loader.loadClass(args[0]);
        Class mainArgType[] = {(new String[0]).getClass()};

        Method main = clas.getMethod("main", mainArgType);

        Object[] argsArray = {progArgs};

        main.invoke(null, argsArray);
    }
}
