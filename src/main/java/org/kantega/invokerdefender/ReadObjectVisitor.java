package org.kantega.invokerdefender;

import org.objectweb.asm.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class ReadObjectVisitor extends ClassVisitor{

    private final String className;
    private String serializableName = Type.getInternalName(Serializable.class);
    private boolean serializable;

    private String readObjectDescription = Type.getMethodDescriptor(Type.VOID_TYPE, Type.getType(ObjectInputStream.class));
    private String[] readObjectExceptions = new String[] {Type.getType(IOException.class).getInternalName(), Type.getType(ClassNotFoundException.class).getInternalName()};
    private boolean hasReadObject = false;
    private String classSignature;
    private int access;

    private static Set<String> serializableTypes = new HashSet<String>();
    private final String onReadObjectCallbackMethod;

    public ReadObjectVisitor(ClassVisitor classVisitor, String className, String onReadObjectCallbackMethod) {
        super(Opcodes.ASM5, classVisitor);
        this.className = className;
        this.onReadObjectCallbackMethod = onReadObjectCallbackMethod;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String supername, String[] interfaces) {
        classSignature = signature;
        this.access = access;
        serializable = findSerializable(interfaces);
        if(serializable || serializableTypes.contains(supername)) {
            serializableTypes.add(name);
        }
        super.visit(version, access, name, signature, supername, interfaces);

    }

    private boolean isInterface() {
        return (access & Opcodes.ACC_INTERFACE) != 0;
    }


    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        if(!isInterface() && isSerializable() && name.equals("readObject") && readObjectDescription.equals(desc)) {
            hasReadObject = true;
            return new MethodVisitor(Opcodes.ASM5, super.visitMethod(access, name, desc, signature, exceptions)) {
                @Override
                public void visitCode() {
                    super.visitCode();
                    mv.visitLdcInsn(className);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getType(DefenderClassFileTransformer.class).getInternalName(), onReadObjectCallbackMethod, "(Ljava/lang/String;)V", false);
                }
            };
        } else {
            return super.visitMethod(access, name, desc, signature, exceptions);
        }
    }

    @Override
    public void visitEnd() {
        if(!isInterface() && isSerializable() && !hasReadObject) {

            MethodVisitor mv = super.visitMethod(Opcodes.ACC_PRIVATE, "readObject", readObjectDescription, null, readObjectExceptions);
            mv.visitCode();
            Label l0 = new Label();
            mv.visitLabel(l0);
            mv.visitLdcInsn(className);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getType(DefenderClassFileTransformer.class).getInternalName(), onReadObjectCallbackMethod, "(Ljava/lang/String;)V", false);
            Label l1 = new Label();
            mv.visitLabel(l1);
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/ObjectInputStream", "defaultReadObject", "()V", false);
            Label l2 = new Label();
            mv.visitLabel(l2);
            mv.visitInsn(Opcodes.RETURN);
            Label l3 = new Label();
            mv.visitLabel(l3);
            mv.visitLocalVariable("this", Type.getObjectType(className).getDescriptor(), classSignature, l0, l3, 0);
            mv.visitLocalVariable("stream", Type.getType(ObjectInputStream.class).getDescriptor(), null, l0, l3, 1);
            mv.visitMaxs(1, 2);
            mv.visitEnd();


        }
        super.visitEnd();
    }

    private boolean findSerializable(String[] interfaces) {
        if(interfaces != null) {
            for (String anInterface : interfaces) {
                if(anInterface.equals(serializableName)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isSerializable() {
        return serializable || serializableTypes.contains(className);
    }
}
