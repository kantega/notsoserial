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

/**
 * Add the check for white/black listed classes to JBoss Marshalling (http://jbossmarshalling.jboss.org/). 
 * 
 * This class supports version 1.2 up to 1.4.10 of Jboss Marshalling and can be used for both Jboss AS and Wildfly.
 */
public class JbossAbstractClassResolverClassVisitor extends ClassVisitor {

    private final String loadClassDesc = "(Ljava/lang/String;)Ljava/lang/Class;";

    private final String callBackDescriptor = "(Ljava/lang/String;)V";

    public JbossAbstractClassResolverClassVisitor(ClassVisitor cv) {
        super(Opcodes.ASM5, cv);
    }


    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
		return new LoadClassCallSiteVisitor(mv);
    }

    public static void onBeforeLoadClass(String className) {
    	Options.getInstance().getNotSoSerial().onBeforeResolveClass(className);
    }

    private class LoadClassCallSiteVisitor extends MethodVisitor {
        public LoadClassCallSiteVisitor(MethodVisitor mv) {
            super(Opcodes.ASM5, mv);
        }
        
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            if (name.equals("loadClass") && loadClassDesc.equals(desc)) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, Type.getType(JbossAbstractClassResolverClassVisitor.class).getInternalName(), "onBeforeLoadClass", callBackDescriptor, false);
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
