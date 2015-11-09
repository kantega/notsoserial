package org.kantega.invokerdefender;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class DefenderClassFileTransformer implements ClassFileTransformer {

    public static final Set<String> unserialized = new HashSet<String>();

    static {
        unserialized.add(internalName("org.​apache.​commons.​collections.​functors.​InvokerTransformer"));
        unserialized.add(internalName("org.​apache.​commons.​collections4.​functors.​InvokerTransformer"));
        unserialized.add(internalName("org.​codehaus.​groovy.​runtime.​ConvertedClosure"));
        unserialized.add(internalName("com.​sun.​org.​apache.​xalan.​internal.​xsltc.​trax.​TemplatesImpl"));
        String classes = System.getProperty("invoker.defender.custom.classes");
        if(classes != null) {
            for (String className : classes.split(",")) {
                className = className.trim();
                unserialized.add(className);
            }
        }
    }

    private static String internalName(String internalName) {
        return internalName;
    }

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if(className != null && className.contains(className)) {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(0);
            reader.accept(new UnserializeVisitor(writer), 0);
            return writer.toByteArray();
        }
        return classfileBuffer;
    }
}
