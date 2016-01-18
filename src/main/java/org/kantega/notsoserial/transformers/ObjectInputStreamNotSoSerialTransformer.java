package org.kantega.notsoserial.transformers;

import org.kantega.notsoserial.NotSoSerialTransformer;
import org.objectweb.asm.ClassVisitor;

/**
 *
 */
public class ObjectInputStreamNotSoSerialTransformer implements NotSoSerialTransformer {
    public boolean shouldRetransform(Class clazz) {
        return "java.io.ObjectInputStream".equals(clazz.getName());
    }

    public boolean shouldTransform(String className) {
        return "java/io/ObjectInputStream".equals(className);
    }

    public ClassVisitor createClassVisitor(ClassVisitor writer) {
        return new ObjectInputStreamClassVisitor(writer);
    }
}
