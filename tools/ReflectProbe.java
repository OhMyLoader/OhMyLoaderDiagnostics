import java.lang.invoke.MethodHandle;
import java.lang.reflect.*;

public class ReflectProbe {
    public static void main(String[] a) throws Exception {
        for (Field f : MethodHandle.class.getDeclaredFields()) {
            if (f.getName().toLowerCase().contains("cache")) System.out.println("MH: " + f);
        }
        Class<?> om = Class.forName("java.lang.runtime.ObjectMethods");
        for (Field f : om.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers())) System.out.println("OM: " + f);
        }
        Class<?> u = Class.forName("sun.misc.Unsafe");
        Field theUnsafe = u.getDeclaredField("theUnsafe");
        theUnsafe.setAccessible(true);
        System.out.println("unsafe=" + theUnsafe.get(null));
        System.out.println("objOff=" + u.getMethod("objectFieldOffset", Field.class));
        System.out.println("sfBase=" + u.getMethod("staticFieldBase", Field.class));
        System.out.println("sfOff=" + u.getMethod("staticFieldOffset", Field.class));
        System.out.println("getObj=" + u.getMethod("getObject", Object.class, long.class));
    }
}
