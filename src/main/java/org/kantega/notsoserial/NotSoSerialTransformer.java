package org.kantega.notsoserial;

import org.objectweb.asm.ClassVisitor;

/**
 *
 */
public interface NotSoSerialTransformer {

    boolean shouldRetransform(Class clazz);
    boolean shouldTransform(String className);
    ClassVisitor createClassVisitor(ClassVisitor writer);
}
