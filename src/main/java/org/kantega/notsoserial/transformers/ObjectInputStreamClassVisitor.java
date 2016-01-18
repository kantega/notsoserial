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

package org.kantega.notsoserial.transformers;

import org.kantega.notsoserial.Options;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.ObjectStreamClass;

/**
 *
 */
public class ObjectInputStreamClassVisitor extends ClassVisitor {

    private final String resolveClassDesc = "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;";

    private final String callBackDescriptor = "(Ljava/io/ObjectStreamClass;)Ljava/io/ObjectStreamClass;";

    public ObjectInputStreamClassVisitor(ClassVisitor cv) {
        super(Opcodes.ASM5, cv);
    }


    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
        return new ResolveClassCallSiteVisitor(mv);
    }

    public static ObjectStreamClass onBeforeResolveClass(ObjectStreamClass desc) {
        String className = desc.getName();
        Options.getInstance().getNotSoSerial().onBeforeResolveClass(className);
        return desc;
    }

    private class ResolveClassCallSiteVisitor extends MethodVisitor {
        public ResolveClassCallSiteVisitor(MethodVisitor mv) {
            super(Opcodes.ASM5, mv);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (name.equals("resolveClass") && resolveClassDesc.equals(desc)) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getType(ObjectInputStreamClassVisitor.class).getInternalName(), "onBeforeResolveClass", callBackDescriptor, false);
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
