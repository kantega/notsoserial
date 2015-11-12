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

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.ObjectStreamClass;

/**
 *
 */
public class ObjectInputStreamClassVisitor extends ClassVisitor {
    private final String callbackMethod;

    private final String resolveClassDesc = Type.getMethodDescriptor(Type.getType(Class.class), Type.getType(ObjectStreamClass.class));

    private final String callBackDescriptor = Type.getMethodDescriptor(Type.getType(ObjectStreamClass.class), Type.getType(ObjectStreamClass.class));

    public ObjectInputStreamClassVisitor(ClassVisitor cv, String callbackMethod) {
        super(Opcodes.ASM5, cv);
        this.callbackMethod = callbackMethod;
    }


    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
        return new ResolveClassCallSiteVisitor(mv);
    }

    private class ResolveClassCallSiteVisitor extends MethodVisitor {
        public ResolveClassCallSiteVisitor(MethodVisitor mv) {
            super(Opcodes.ASM5, mv);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (name.equals("resolveClass") && resolveClassDesc.equals(desc)) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getType(NotSoSerialClassFileTransformer.class).getInternalName(), callbackMethod, callBackDescriptor, false);
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
